// extracted via
// HEADER_PATH="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/ESTypes.h'
// awk '/,*ES_EVENT_TYPE/ && ! /\/\// && ! /\*/ {print $0}'  > ~/vastlimits/ESClientTest/ESClientTest/Types.h

#include <unordered_map>
#include "EndpointSecurity/EndpointSecurity.h"

namespace ESEventTypes
{
   const std::unordered_map<std::string, es_event_type_t> name2event {
     {"AUTH_EXEC", ES_EVENT_TYPE_AUTH_EXEC},
     {"AUTH_OPEN", ES_EVENT_TYPE_AUTH_OPEN},
     {"AUTH_KEXTLOAD", ES_EVENT_TYPE_AUTH_KEXTLOAD},
     {"AUTH_MMAP", ES_EVENT_TYPE_AUTH_MMAP},
     {"AUTH_MPROTECT", ES_EVENT_TYPE_AUTH_MPROTECT},
     {"AUTH_MOUNT", ES_EVENT_TYPE_AUTH_MOUNT},
     {"AUTH_RENAME", ES_EVENT_TYPE_AUTH_RENAME},
     {"AUTH_SIGNAL", ES_EVENT_TYPE_AUTH_SIGNAL},
     {"AUTH_UNLINK", ES_EVENT_TYPE_AUTH_UNLINK},
     {"NOTIFY_EXEC", ES_EVENT_TYPE_NOTIFY_EXEC},
     {"NOTIFY_OPEN", ES_EVENT_TYPE_NOTIFY_OPEN},
     {"NOTIFY_FORK", ES_EVENT_TYPE_NOTIFY_FORK},
     {"NOTIFY_CLOSE", ES_EVENT_TYPE_NOTIFY_CLOSE},
     {"NOTIFY_CREATE", ES_EVENT_TYPE_NOTIFY_CREATE},
     {"NOTIFY_EXCHANGEDATA", ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA},
     {"NOTIFY_EXIT", ES_EVENT_TYPE_NOTIFY_EXIT},
     {"NOTIFY_GET_TASK", ES_EVENT_TYPE_NOTIFY_GET_TASK},
     {"NOTIFY_KEXTLOAD", ES_EVENT_TYPE_NOTIFY_KEXTLOAD},
     {"NOTIFY_KEXTUNLOAD", ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD},
     {"NOTIFY_LINK", ES_EVENT_TYPE_NOTIFY_LINK},
     {"NOTIFY_MMAP", ES_EVENT_TYPE_NOTIFY_MMAP},
     {"NOTIFY_MPROTECT", ES_EVENT_TYPE_NOTIFY_MPROTECT},
     {"NOTIFY_MOUNT", ES_EVENT_TYPE_NOTIFY_MOUNT},
     {"NOTIFY_UNMOUNT", ES_EVENT_TYPE_NOTIFY_UNMOUNT},
     {"NOTIFY_IOKIT_OPEN", ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN},
     {"NOTIFY_RENAME", ES_EVENT_TYPE_NOTIFY_RENAME},
     {"NOTIFY_SETATTRLIST", ES_EVENT_TYPE_NOTIFY_SETATTRLIST},
     {"NOTIFY_SETEXTATTR", ES_EVENT_TYPE_NOTIFY_SETEXTATTR},
     {"NOTIFY_SETFLAGS", ES_EVENT_TYPE_NOTIFY_SETFLAGS},
     {"NOTIFY_SETMODE", ES_EVENT_TYPE_NOTIFY_SETMODE},
     {"NOTIFY_SETOWNER", ES_EVENT_TYPE_NOTIFY_SETOWNER},
     {"NOTIFY_SIGNAL", ES_EVENT_TYPE_NOTIFY_SIGNAL},
     {"NOTIFY_UNLINK", ES_EVENT_TYPE_NOTIFY_UNLINK},
     {"NOTIFY_WRITE", ES_EVENT_TYPE_NOTIFY_WRITE},
     {"AUTH_FILE_PROVIDER_MATERIALIZE", ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE},
     {"NOTIFY_FILE_PROVIDER_MATERIALIZE", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE},
     {"AUTH_FILE_PROVIDER_UPDATE", ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE},
     {"NOTIFY_FILE_PROVIDER_UPDATE", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE},
     {"AUTH_READLINK", ES_EVENT_TYPE_AUTH_READLINK},
     {"NOTIFY_READLINK", ES_EVENT_TYPE_NOTIFY_READLINK},
     {"AUTH_TRUNCATE", ES_EVENT_TYPE_AUTH_TRUNCATE},
     {"NOTIFY_TRUNCATE", ES_EVENT_TYPE_NOTIFY_TRUNCATE},
     {"AUTH_LINK", ES_EVENT_TYPE_AUTH_LINK},
     {"NOTIFY_LOOKUP", ES_EVENT_TYPE_NOTIFY_LOOKUP},
     {"AUTH_CREATE", ES_EVENT_TYPE_AUTH_CREATE},
     {"AUTH_SETATTRLIST", ES_EVENT_TYPE_AUTH_SETATTRLIST},
     {"AUTH_SETEXTATTR", ES_EVENT_TYPE_AUTH_SETEXTATTR},
     {"AUTH_SETFLAGS", ES_EVENT_TYPE_AUTH_SETFLAGS},
     {"AUTH_SETMODE", ES_EVENT_TYPE_AUTH_SETMODE},
     {"AUTH_SETOWNER", ES_EVENT_TYPE_AUTH_SETOWNER},
     {"AUTH_CHDIR", ES_EVENT_TYPE_AUTH_CHDIR},
     {"NOTIFY_CHDIR", ES_EVENT_TYPE_NOTIFY_CHDIR},
     {"AUTH_GETATTRLIST", ES_EVENT_TYPE_AUTH_GETATTRLIST},
     {"NOTIFY_GETATTRLIST", ES_EVENT_TYPE_NOTIFY_GETATTRLIST},
     {"NOTIFY_STAT", ES_EVENT_TYPE_NOTIFY_STAT},
     {"NOTIFY_ACCESS", ES_EVENT_TYPE_NOTIFY_ACCESS},
     {"AUTH_CHROOT", ES_EVENT_TYPE_AUTH_CHROOT},
     {"NOTIFY_CHROOT", ES_EVENT_TYPE_NOTIFY_CHROOT},
     {"AUTH_UTIMES", ES_EVENT_TYPE_AUTH_UTIMES},
     {"NOTIFY_UTIMES", ES_EVENT_TYPE_NOTIFY_UTIMES},
     {"AUTH_CLONE", ES_EVENT_TYPE_AUTH_CLONE},
     {"NOTIFY_CLONE", ES_EVENT_TYPE_NOTIFY_CLONE},
     {"NOTIFY_FCNTL", ES_EVENT_TYPE_NOTIFY_FCNTL},
     {"AUTH_GETEXTATTR", ES_EVENT_TYPE_AUTH_GETEXTATTR},
     {"NOTIFY_GETEXTATTR", ES_EVENT_TYPE_NOTIFY_GETEXTATTR},
     {"AUTH_LISTEXTATTR", ES_EVENT_TYPE_AUTH_LISTEXTATTR},
     {"NOTIFY_LISTEXTATTR", ES_EVENT_TYPE_NOTIFY_LISTEXTATTR},
     {"AUTH_READDIR", ES_EVENT_TYPE_AUTH_READDIR},
     {"NOTIFY_READDIR", ES_EVENT_TYPE_NOTIFY_READDIR},
     {"AUTH_DELETEEXTATTR", ES_EVENT_TYPE_AUTH_DELETEEXTATTR},
     {"NOTIFY_DELETEEXTATTR", ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR},
     {"AUTH_FSGETPATH", ES_EVENT_TYPE_AUTH_FSGETPATH},
     {"NOTIFY_FSGETPATH", ES_EVENT_TYPE_NOTIFY_FSGETPATH},
     {"NOTIFY_DUP", ES_EVENT_TYPE_NOTIFY_DUP},
     {"AUTH_SETTIME", ES_EVENT_TYPE_AUTH_SETTIME},
     {"NOTIFY_SETTIME", ES_EVENT_TYPE_NOTIFY_SETTIME},
     {"NOTIFY_UIPC_BIND", ES_EVENT_TYPE_NOTIFY_UIPC_BIND},
     {"AUTH_UIPC_BIND", ES_EVENT_TYPE_AUTH_UIPC_BIND},
     {"NOTIFY_UIPC_CONNECT", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT},
     {"AUTH_UIPC_CONNECT", ES_EVENT_TYPE_AUTH_UIPC_CONNECT},
     {"AUTH_EXCHANGEDATA", ES_EVENT_TYPE_AUTH_EXCHANGEDATA},
     {"AUTH_SETACL", ES_EVENT_TYPE_AUTH_SETACL},
     {"NOTIFY_SETACL", ES_EVENT_TYPE_NOTIFY_SETACL},
     {"NOTIFY_PTY_GRANT", ES_EVENT_TYPE_NOTIFY_PTY_GRANT},
     {"NOTIFY_PTY_CLOSE", ES_EVENT_TYPE_NOTIFY_PTY_CLOSE},
     {"AUTH_PROC_CHECK", ES_EVENT_TYPE_AUTH_PROC_CHECK},
     {"NOTIFY_PROC_CHECK", ES_EVENT_TYPE_NOTIFY_PROC_CHECK},
     {"AUTH_GET_TASK", ES_EVENT_TYPE_AUTH_GET_TASK},
     {"AUTH_SEARCHFS", ES_EVENT_TYPE_AUTH_SEARCHFS},
     {"NOTIFY_SEARCHFS", ES_EVENT_TYPE_NOTIFY_SEARCHFS},
     {"AUTH_FCNTL", ES_EVENT_TYPE_AUTH_FCNTL},
     {"AUTH_IOKIT_OPEN", ES_EVENT_TYPE_AUTH_IOKIT_OPEN},
     {"AUTH_PROC_SUSPEND_RESUME", ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME},
     {"NOTIFY_PROC_SUSPEND_RESUME", ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME},
     {"NOTIFY_CS_INVALIDATED", ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED},
     {"NOTIFY_GET_TASK_NAME", ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME},
     {"NOTIFY_TRACE", ES_EVENT_TYPE_NOTIFY_TRACE},
     {"NOTIFY_REMOTE_THREAD_CREATE", ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE},
     {"AUTH_REMOUNT", ES_EVENT_TYPE_AUTH_REMOUNT},
     {"NOTIFY_REMOUNT", ES_EVENT_TYPE_NOTIFY_REMOUNT},
     {"AUTH_GET_TASK_READ", ES_EVENT_TYPE_AUTH_GET_TASK_READ},
     {"NOTIFY_GET_TASK_READ", ES_EVENT_TYPE_NOTIFY_GET_TASK_READ},
     {"NOTIFY_GET_TASK_INSPECT", ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT},
     {"NOTIFY_SETUID", ES_EVENT_TYPE_NOTIFY_SETUID},
     {"NOTIFY_SETGID", ES_EVENT_TYPE_NOTIFY_SETGID},
     {"NOTIFY_SETEUID", ES_EVENT_TYPE_NOTIFY_SETEUID},
     {"NOTIFY_SETEGID", ES_EVENT_TYPE_NOTIFY_SETEGID},
     {"NOTIFY_SETREUID", ES_EVENT_TYPE_NOTIFY_SETREUID},
     {"NOTIFY_SETREGID", ES_EVENT_TYPE_NOTIFY_SETREGID},
     {"AUTH_COPYFILE", ES_EVENT_TYPE_AUTH_COPYFILE},
     {"NOTIFY_COPYFILE", ES_EVENT_TYPE_NOTIFY_COPYFILE}
   };

   inline std::unordered_map<es_event_type_t, std::string> getEvent2Name(const std::unordered_map<std::string, es_event_type_t>& events2names)
   {
      std::unordered_map<es_event_type_t, std::string> event2name {};
      
      for (const auto& [name, eventType] : events2names)
      {
         event2name.emplace(eventType, name);
      }
      return event2name;
   }

   const std::unordered_map<es_event_type_t, std::string> event2name = getEvent2Name(name2event);
}
