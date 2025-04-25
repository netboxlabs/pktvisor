#pragma once

#define NOMINMAX

#include "visor_config.h"

#ifndef CRASHPAD_NOT_SUPPORTED
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <client/crash_report_database.h>
#include <client/crashpad_client.h>
#include <client/settings.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace crashpad {

static bool start_crashpad_handler(std::string token, std::string url, std::string user_defined, base::FilePath::StringType handler_path)
{
    std::map<std::string, std::string> annotations;
    std::vector<std::string> arguments;
    CrashpadClient client;
    bool rc;

    annotations["format"] = "minidump";
    annotations["product"] = "pktvisor";
    annotations["database"] = "pktvisor";
    annotations["version"] = VISOR_VERSION_NUM;
    annotations["user_defined"] = user_defined;
    annotations["token"] = token;
    arguments.push_back("--no-rate-limit");

#ifdef _WIN32
    base::FilePath::StringType db_path(L"crashpad");
#else
    base::FilePath::StringType db_path("crashpad");
#endif

    base::FilePath db(db_path);
    base::FilePath handler(handler_path);

    std::unique_ptr<CrashReportDatabase> database = crashpad::CrashReportDatabase::Initialize(db);

    if (database == nullptr || database->GetSettings() == NULL)
        return false;

    /* Enable automated uploads. */
    database->GetSettings()->SetUploadsEnabled(true);

    rc = client.StartHandler(handler, db, db, url, "", annotations, arguments, true, false);
    if (rc == false) {
        return false;
    }
    return true;
}
}
#else
namespace base {
namespace FilePath {
typedef std::string StringType;
}
}

namespace crashpad {
static bool start_crashpad_handler(std::string, std::string, std::string, base::FilePath::StringType)
{
    return false;
}
}
#endif