#include <CLI11.h>
#include "Types.h"
#include "EndpointSecurity/EndpointSecurity.h"
#include <dispatch/dispatch.h>

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <array>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <signal.h>
#include <chrono>
#include <locale>
#include <mutex>


constexpr const char* RESET =  "\033[0m";
// indicator colors
constexpr const char* RED   =  "\033[31m";
constexpr const char* GREEN =  "\033[32m";
// colors for grouping
constexpr const char* YELLOW = "\u001b[33m";
constexpr const char* BRIGHT_YELLOW = "\u001b[33;1m";
constexpr const char* BLUE = "\u001b[34m";
constexpr const char* BRIGHT_BLUE = "\u001b[34;1m";
constexpr const char* MAGENTA = "\u001b[35;m";
constexpr const char* BRIGHT_MAGENTA = "\u001b[35;1m";
constexpr const char* CYAN = "\u001b[36;m";
constexpr const char* BRIGHT_CYAN = "\u001b[36;1m";

const std::vector<const char*> groupColors {
   BRIGHT_YELLOW,
   BRIGHT_BLUE,
   BRIGHT_MAGENTA,
   BRIGHT_CYAN
};

const std::vector<const char*> subGroupColors {
   YELLOW,
   BLUE,
   MAGENTA,
   CYAN
};



struct EventCounts
{
   int totalCount {0};
   int numMissingMessages {0};
   uint64_t prevEventSeqNumber {0};
};

struct AppEventCounts
{
   int numExecSourceEvents {0};
   int numExecTargetEvents {0};
   int numExitEvents {0};
   int numForkEvents {0};
   /// execs the observed executable performs itself and the respective counts
   std::unordered_map<std::string, int> sourceExecs {};
   /// map of parent processes exec'ing into the observed executable
   std::unordered_map<std::string, int> parentExecs {};
};

namespace global
{
   auto intervalStart = std::chrono::steady_clock::now();
   
   std::vector<es_event_type_t> events2subscribe2 {};
   std::mutex events2subscribe2Mutex;

   /// collects executable names from the command line, only written to during parsing
   std::vector<std::string> apps;
   /// maps application names to their corresponding event counts
   std::unordered_map<std::string, AppEventCounts> appStatistics {};
   std::mutex appStatisticsMutex;

   /// maps event type names to their corresponding message counts
   std::unordered_map<std::string, EventCounts> eventStatistics {};
   std::mutex eventStatisticsMutex;

   bool printChildProcessFlag {false};
   bool printParentProcessFlag {false};
   bool cumulativeStatistics {false};
}


void countEventMessages(const es_message_t* msg)
{
   std::scoped_lock lock {global::eventStatisticsMutex};
   if (global::eventStatistics.contains(ESEventTypes::event2name.at(msg->event_type)))
   {
      auto& eventCounts = global::eventStatistics.at(ESEventTypes::event2name.at((msg->event_type)));
      eventCounts.totalCount++;
      if (msg->seq_num > 0
          && msg->seq_num - eventCounts.prevEventSeqNumber > 1)
      {
         eventCounts.numMissingMessages += msg->seq_num - eventCounts.prevEventSeqNumber;
      }
      eventCounts.prevEventSeqNumber = msg->seq_num;
   }
}

void countProcessMessages(const es_message_t* msg)
{
   auto getExecutableName = [](const char* path) -> std::string {
      return std::filesystem::path(path).filename().string();
   };
   
   /// the process that took the action
   const auto sourceProcessName = getExecutableName(msg->process->executable->path.data);
   
   std::lock_guard guard {global::appStatisticsMutex};
   switch (msg->event_type) {
      case ES_EVENT_TYPE_NOTIFY_EXEC:
      {
         /// target of exec
         const auto targetProcessName = getExecutableName(msg->event.exec.target->executable->path.data);
         // the observed executable is the target of exec
         if (global::appStatistics.contains(targetProcessName))
         {
            global::appStatistics[targetProcessName].numExecTargetEvents++;
            // store the parent process which performed the exec
            global::appStatistics[targetProcessName].parentExecs[sourceProcessName]++;
         }
         // the observed executable is the source of exec
         if (global::appStatistics.contains(sourceProcessName))
         {
            global::appStatistics[sourceProcessName].numExecSourceEvents++;
            // store the child process in which the observed executable execs into
            global::appStatistics[sourceProcessName].sourceExecs[targetProcessName]++;
         }
         break;
      }
      case ES_EVENT_TYPE_NOTIFY_EXIT:
      {
         if (global::appStatistics.contains(sourceProcessName))
         {
            global::appStatistics[sourceProcessName].numExitEvents++;
         }
         break;
      }
      case ES_EVENT_TYPE_NOTIFY_FORK:
      {
         if (global::appStatistics.contains(sourceProcessName))
         {
            global::appStatistics[sourceProcessName].numForkEvents++;
         }
         break;
      }
         
      default:
         break;

   }
}

void handle_event([[maybe_unused]] es_client_t* client, const es_message_t* msg)
{
   switch (msg->event_type)
   {
      case ES_EVENT_TYPE_NOTIFY_EXEC:
      case ES_EVENT_TYPE_NOTIFY_EXIT:
      case ES_EVENT_TYPE_NOTIFY_FORK: countProcessMessages(msg);
         
      default: countEventMessages(msg);
   }
}


template<size_t SIZE>
void printHeader(const std::string& separator, const std::array<std::string, SIZE>& headers, const std::unordered_map<std::string, size_t>& maxColumnWidths)
{
   using namespace std;
   cout << separator << "\n" << left;
   for (const auto& header : headers)
   {
      cout << "| " << setw(static_cast<int>(maxColumnWidths.at(header))) << header << " ";
   }
   cout << "|\n";
   cout << separator << "\n";
}

void printStatisticsByExecutable()
{
   using namespace std;
   constexpr size_t numColumns = 6;
   
   string executableColumn {"executable"};
   string execSourceColumn {"#exec_source_events"};
   string execTargetColumn {"#exec_target_events"};
   string forkColumn {"#fork_events"};
   string exitColumn {"#exit_events"};
   string deltaColumn {" delta "};
   
   const array<string, numColumns> headers {
      executableColumn,
      execSourceColumn,
      execTargetColumn,
      forkColumn,
      exitColumn,
      deltaColumn,
   };
   // calculate approriate column widths
   
   // use the longest element in the first column (consisting of header + app names) for the maximum width
   static const size_t longestAppNameLength = std::max_element(global::apps.begin(), global::apps.end(), [](const auto& a, const auto& b) {
      return a.length() < b.length();
   })->length();
   static auto maxColumnWidth_c1 = std::max(longestAppNameLength, headers[0].length());
   
   auto getLongestStringKey = [](const auto& a, const auto& b) {
      return a.first.length() < b.first.length();
   };
   
   scoped_lock lock {global::appStatisticsMutex};
   size_t longestChildNameLength {0};
   if (global::printChildProcessFlag)
   {
      for (const auto& [app, appStats] : global::appStatistics)
      {
         if (!appStats.sourceExecs.empty())
            longestChildNameLength = std::max(longestChildNameLength, std::max_element(appStats.sourceExecs.begin(), appStats.sourceExecs.end(), getLongestStringKey)->first.length());
      }
      longestChildNameLength += 2; // account for formatting with --
   }
   
   size_t longestParentNameLength {0};
   if (global::printParentProcessFlag)
   {
      for (const auto& [app, appStats] : global::appStatistics)
      {
         if (!appStats.parentExecs.empty())
            longestParentNameLength = std::max(longestParentNameLength, std::max_element(appStats.parentExecs.begin(), appStats.parentExecs.end(), getLongestStringKey)->first.length());
      }
      longestParentNameLength += 2; // account for formatting with --
   }
   
   vector<size_t> longestLengths {longestAppNameLength, longestChildNameLength, longestParentNameLength, headers[0].length()};
   maxColumnWidth_c1 = *std::max_element(longestLengths.begin(), longestLengths.end());
   
   unordered_map<string, size_t> maxColumnWidths {};
   for (const auto& header : headers)
   {
      if (header == executableColumn)
         maxColumnWidths[header] = maxColumnWidth_c1;
      else
         maxColumnWidths[header] = header.length();
   }
   
   // create and print separator
   string separator {"+"};
   for (const auto& header : headers)
   {
      separator += string(maxColumnWidths.at(header) + 2, '-');
      separator += "+";
   }
   
   printHeader(separator, headers, maxColumnWidths);
   
   // gather and print statistics lines
   int colorIdx = 0;
   for (auto& [appName, appEventCounts] : global::appStatistics)
   {
      int delta = appEventCounts.numExecTargetEvents
                  + appEventCounts.numForkEvents
                  - appEventCounts.numExecSourceEvents
                  - appEventCounts.numExitEvents;
      
      colorIdx %= groupColors.size();
      cout << "| " << left << ((global::printChildProcessFlag || global::printParentProcessFlag) ? groupColors[colorIdx] : "") << std::setw(static_cast<int>(maxColumnWidths[executableColumn])) << appName << RESET
         << " | " << std::setw(static_cast<int>(maxColumnWidths[execSourceColumn])) << right << appEventCounts.numExecSourceEvents
         << " | " << std::setw(static_cast<int>(maxColumnWidths[execTargetColumn])) << appEventCounts.numExecTargetEvents
         << " | " << std::setw(static_cast<int>(maxColumnWidths[forkColumn])) << appEventCounts.numForkEvents
         << " | " << std::setw(static_cast<int>(maxColumnWidths[exitColumn])) << appEventCounts.numExitEvents
         << " | " << (delta != 0 ? RED : GREEN) << setw(static_cast<int>(maxColumnWidths[deltaColumn])) << delta << RESET
         << " | " << (delta != 0 ? "❌" : "✅") << "\n";
      cout << separator << "\n";
      
      if (global::printChildProcessFlag)
      {
         // the source execs of the observed app are listed in their own target exec column
         for (auto& [sourceExecApp, sourceExecAppCount] : appEventCounts.sourceExecs)
         {
            cout << "| " << left << subGroupColors[colorIdx] << std::setw(static_cast<int>(maxColumnWidths[executableColumn])) << "--" + sourceExecApp << RESET
               << " | " << std::setw(static_cast<int>(maxColumnWidths[execSourceColumn])) << right << "-"
               << " | " << std::setw(static_cast<int>(maxColumnWidths[execTargetColumn])) << sourceExecAppCount
               << " | " << std::setw(static_cast<int>(maxColumnWidths[forkColumn])) << "-"
               << " | " << std::setw(static_cast<int>(maxColumnWidths[exitColumn])) << "-"
               << " | " << setw(static_cast<int>(maxColumnWidths[deltaColumn])) << "-"
               << " | " << "🐣" <<"\n";
            cout << separator << "\n";
         }
      }
      
      if (global::printParentProcessFlag)
      {
         for (auto& [parentApp, parentExecAppCount] : appEventCounts.parentExecs)
         {
            cout << "| " << left << subGroupColors[colorIdx] << std::setw(static_cast<int>(maxColumnWidths[executableColumn])) << "--" + parentApp << RESET
               << " | " << std::setw(static_cast<int>(maxColumnWidths[execSourceColumn])) << right << parentExecAppCount
               << " | " << std::setw(static_cast<int>(maxColumnWidths[execTargetColumn])) << "-"
               << " | " << std::setw(static_cast<int>(maxColumnWidths[forkColumn])) << "-"
               << " | " << std::setw(static_cast<int>(maxColumnWidths[exitColumn])) << "-"
               << " | " << setw(static_cast<int>(maxColumnWidths[deltaColumn])) << "-"
               << " | " << "👨‍👩‍👦" <<"\n";
            cout << separator << "\n";
         }
      }
      
      if (!global::cumulativeStatistics)
      {
         // clean up between intervals
         appEventCounts.sourceExecs.clear();
         appEventCounts.parentExecs.clear();
         appEventCounts.numExecSourceEvents = 0;
         appEventCounts.numExecTargetEvents = 0;
         appEventCounts.numForkEvents = 0;
         appEventCounts.numExitEvents = 0;
      }
         
      colorIdx++;
   }
}

size_t getMaximumEventColumnWidth(const std::string& header, const std::vector<es_event_type_t>& values)
{
   // combine column header and row values
   std::vector<std::string> columnValues {values.size() + 1};
   columnValues[0] = header;
   std::transform(values.begin(), values.end(), columnValues.begin() + 1, [](es_event_type_t eventType) {
      return ESEventTypes::event2name.at(eventType);
   });
   
   auto maxElem = std::max_element(columnValues.begin(), columnValues.end(), [](const auto& a, const auto& b) {
      return a.length() < b.length();
   });
   return maxElem->length();
}

void printStatisticsByEventType()
{
   constexpr size_t numColumns = 3;
   using namespace std;
   
   string eventTypeColumn = "ES_event_type";
   string messagesReceivedColumn = "#messages_received";
   string messagesMissingColumn = "#messages_missing";
   
   const array<string, numColumns> headers = {
      eventTypeColumn,
      messagesReceivedColumn,
      messagesMissingColumn
   };
   static auto maxColumnWidth_c1 = getMaximumEventColumnWidth(headers[0], global::events2subscribe2);
   
   static const unordered_map<string, size_t> maxColumnWidths {
      {eventTypeColumn, maxColumnWidth_c1},
      {messagesReceivedColumn, headers[1].length()},
      {messagesMissingColumn, headers[2].length()}
   };
   
   string separator {"+"};
   for (const auto& header : headers)
   {
      separator += string(maxColumnWidths.at(header) + 2, '-');
      separator += "+";
   }

   printHeader(separator, headers, maxColumnWidths);
   
   uint64_t totalReceivedMessages {0};
   uint64_t totalMissedMessages {0};
   
   scoped_lock lock {global::eventStatisticsMutex};
   for (auto& [eventName, eventCounts] : global::eventStatistics)
   {
      totalReceivedMessages += eventCounts.totalCount;
      totalMissedMessages += eventCounts.numMissingMessages;
      
      std::cout << "| " << left << std::setw(static_cast<int>(maxColumnWidths.at(eventTypeColumn))) << eventName
               << " | " << std::setw(static_cast<int>(maxColumnWidths.at(messagesReceivedColumn))) << right << eventCounts.totalCount
               << " | " << (eventCounts.numMissingMessages != 0 ? RED : GREEN) << std::setw(static_cast<int>(maxColumnWidths.at(messagesMissingColumn))) << eventCounts.numMissingMessages << RESET
               << " | " << (eventCounts.numMissingMessages != 0 ? "❌" : "✅") << "\n";
      std::cout << separator << "\n";
      
      if (!global::cumulativeStatistics)
      {
         eventCounts.totalCount = 0;
         eventCounts.numMissingMessages = 0;
      }
   }
   
   std::cout << "| " << right << std::setw(static_cast<int>(maxColumnWidths.at(eventTypeColumn))) << "total:"
            << " | " << std::setw(static_cast<int>(maxColumnWidths.at(messagesReceivedColumn))) << totalReceivedMessages
            << " | " << (totalMissedMessages != 0 ? RED : GREEN) << std::setw(static_cast<int>(maxColumnWidths.at(messagesMissingColumn))) << totalMissedMessages << RESET
            << " | " << (totalMissedMessages != 0 ? "❌" : "✅") << "\n";
   std::cout << separator << "\n";
   
}


/// Is called when the user presses ctrl + t to send SIGINFO
void sigHandler()
{
   using namespace std;
   using namespace std::chrono;
   static int signalCounter {0};
   signalCounter++;
   
   std::cout << "\n🚀 ES client statistics #" << signalCounter << ":" << "\n";
   
   if (!global::apps.empty())
      printStatisticsByExecutable();
   std::cout << "\n";
   printStatisticsByEventType();
   
   auto intervalEnd = steady_clock::now();
   auto intervalDuration = intervalEnd - global::intervalStart;

   std::cout << "⏱ interval duration: " << duration_cast<seconds>(intervalDuration).count() << " seconds\n";
   global::intervalStart = steady_clock::now();
}

/// to format numbers seperated by thousands
// https://en.cppreference.com/w/cpp/locale/numpunct/grouping
struct space_out : std::numpunct<char>
{
   char do_thousands_sep() const { return '.'; }
   std::string do_grouping() const { return "\3"; }
};


int main(int argc, char* argv[])
{
   // parse command line
   // https://github.com/CLIUtils/CLI11
   // https://cliutils.github.io/CLI11/book/chapters/basics.html
   CLI::App app{"Endpoint Security Message Analysis Tool - esmat by ∞ vast limits GmbH\n\n"
      "Prints statistics for Endpoint Security messages between two SIGINFO signals (ctrl + t). \n"
      "Must be run as root to be able to subscribe to Endpoint Security events.\n\n"
      "Examples: \n"
      "sudo ./esmat.app/Contents/MacOS/esmat -a ls git\n\n"
      "sudo ./esmat.app/Contents/MacOS/esmat -e NOTIFY_PTY_GRANT NOTIFY_PTY_CLOSE -a sshd\n\n"
      "sudo ./esmat.app/Contents/MacOS/esmat -a xpcproxy -pc\n\n"
   };
   app.add_option("-a,--apps", global::apps,
                  "Add executable names to watch events for. \n"
                  "If one or more executable names are specified as arguments, \n"
                  "the event types NOTIFY_EXEC, NOTIFY_FORK and NOTIFY_EXIT are automatically enabled. \n"
                  );
   std::set<std::string> additionalEventTypes {};
   app.add_option("-e, --events", additionalEventTypes,
                  "Define which ES event types you want to see statistics for.\n"
                  "NOTIFY_EXEC, NOTIFY_FORK and NOTIFY_EXIT are automatically enabled\n"
                  "if arguments are provided via the -a option.\n"
                  "Note: AUTH events are currently not supported.\n");
   bool printAvailableEvents {false};
   app.add_flag("-E,--events-available", printAvailableEvents,
                "Prints a list of available Endpoint Security event types.\n"
                "Note: Not all listed events are available on every version of macOS.\n"
                "Only the newest macOS version typically supports all events.\n");
   app.add_flag("-p,--parent", global::printParentProcessFlag,
                  "Shows which parent processes have exec'ed into the processes specified via -a.\n");
   app.add_flag("-c,--child", global::printChildProcessFlag,
                  "Include child processes which the via -a specified processes exec into.\n");
   
   app.add_flag("-C,--cumulative", global::cumulativeStatistics,
                "If set statistics are never reset between intervals.");
   
   CLI11_PARSE(app, argc, argv);
   
   if (printAvailableEvents)
   {
      std::cout << "Available Endpoint Security events:" << "\n";
      int count {1};
      for (const auto& [eventName, _] : ESEventTypes::name2event) {
         if (eventName.starts_with("NOTIFY_")) {
            std::cout << std::setw(3) << count++ <<". " << eventName << "\n";
         }
      }
      exit(0);
   }
   

   if (getuid() != 0)
   {
      std::cerr << "App must be run as root. Only root can subscribe to Endpoint Security." << std::endl;
      exit(3);
   }
   
   // thousands separator
   std::cout.imbue(std::locale(std::cout.getloc(), new space_out));
   
   if (global::apps.size() > 0)
   {
      // store executable names to monitor
      for (const auto& appName : global::apps)
      {
         global::appStatistics.emplace(appName, AppEventCounts());
      }
   }
   std::cout << "Press ctrl + t to get event statistics. Statistics will" << (global::cumulativeStatistics ? " NOT " : " ") <<  "be reset after each query" << "\n";
   
   es_client_t* client;
   es_new_client_result_t result = es_new_client(
     &client, ^(es_client_t* c, const es_message_t* msg) {
       handle_event(c, msg);
     }
   );

   if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
   {
      std::cerr << "Couldn't connect to Endpoint Security: ";
      switch (result) {
         case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            std::cerr << "missing TCC approval for Full Disk Access\n" << "\n";
            return 1;
         case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            std::cerr << "the caller isn't properly entitled\n";
            return 1;
            
         default:
            std::cerr << "error " << result << " occured while trying to connect" << result << "\n";;
            return 1;
      }
   }
         

   if (!global::apps.empty())
   {
      global::events2subscribe2.push_back(ES_EVENT_TYPE_NOTIFY_EXEC);
      global::events2subscribe2.push_back(ES_EVENT_TYPE_NOTIFY_FORK);
      global::events2subscribe2.push_back(ES_EVENT_TYPE_NOTIFY_EXIT);
   }

   if (!additionalEventTypes.empty())
   {
      std::scoped_lock lock {global::events2subscribe2Mutex};
      for (const auto& eventName : additionalEventTypes)
      {
         std::string eventNameUpper = eventName;
         std::transform(eventNameUpper.begin(), eventNameUpper.end(), eventNameUpper.begin(), toupper);
         std::cout << "Adding " << eventNameUpper << " to observed events" << "\n";
         if (ESEventTypes::name2event.contains(eventNameUpper))
         {
            global::events2subscribe2.push_back(ESEventTypes::name2event.at(eventNameUpper));
         }
         else
         {
            std::cerr << eventNameUpper << " is not a valid ES event type" << "\n";
            return 2;
         }
      }
   }
   
   // subscribe to ES
   es_event_type_t* events = global::events2subscribe2.data();
   auto count = static_cast<unsigned int>(global::events2subscribe2.size());

   if (es_subscribe(client, events, count) != ES_RETURN_SUCCESS)
   {
      std::cerr << "Failed to subscribe to events\n";
      es_delete_client(client);
      return 3;
   }
   
   // set up event statistics
   {
      std::scoped_lock lock {global::eventStatisticsMutex};
      for (const auto& event : global::events2subscribe2)
      {
         global::eventStatistics.emplace(ESEventTypes::event2name.at(event), EventCounts());
      }
   }
   
   // set up signal handling
   dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
   dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINFO, 0, queue);

   if (source)
   {
      dispatch_source_set_event_handler(source, ^{
         sigHandler();
      });
   }
   
#ifdef DEBUG
   // print initial row during debug to check formatting
   sigHandler();
#endif
   // dispatch signal handling
   dispatch_resume(source);
   
   // dispatch es client
   dispatch_main();

   
}


