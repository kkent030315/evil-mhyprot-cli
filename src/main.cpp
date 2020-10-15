#include <iostream>

#include "logger.hpp"
#include "win_utils.hpp"
#include "mhyprot.hpp"
#include "sup.hpp"

#define CONTAINS(src, part) (src.find(part) != std::string::npos)

#define PRINT_USAGE()                                           \
logger::log("[-] incorrect usage\n");                           \
logger::log("[+] usage: bin.exe [process name] [option]\n");    \
logger::log("[+] example: bin.exe notepad.exe -t\n");           \
logger::log("[+] options:\n");                                  \
logger::log("  multiple options are available\n");              \
logger::log("      t: test\n");                                 \
logger::log("      d: debug prints\n");                         \
logger::log("      s: print seeds\n");                          \

//
// main entry point of this cli
//
int main(int argc, const char** argv)
{
    if (argc < 3)
    {
        PRINT_USAGE();
        return -1;
    }

    const std::string option(argv[2]);

    if (!CONTAINS(option, "-"))
    {
        PRINT_USAGE();
        return -1;
    }

    //
    // find process id
    //
    const uint32_t process_id = win_utils::find_process_id(argv[1]);

    if (!process_id)
    {
        logger::log("[!] process \"%s\ was not found\n", argv[1]);
        return -1;
    }

    logger::log("[+] %s (%d)\n", argv[1], process_id);

    //
    // initialize its service, etc
    //
    if (!mhyprot::init())
    {
        logger::log("[!] failed to initialize vulnerable driver\n");
        return -1;
    }

    //
    // initialize driver implementations
    //
    if (!mhyprot::driver_impl::driver_init(
        CONTAINS(option, "d"), // print debug
        CONTAINS(option, "s")  // print seedmap
    ))
    {
        logger::log("[!] failed to initialize driver properly\n");
        mhyprot::unload();
        return -1;
    }

    //
    // perform tests
    //
    if (CONTAINS(option, "t"))
        sup::perform_tests(process_id);

    mhyprot::unload();
    logger::log("[<] done!\n");

    return 0;
}