#include "contiki.h"
#include "shell.h"
#include "serial-shell.h"
#include "collect-view.h"

#define WITH_COFFEE 0

/*---------------------------------------------------------------------------*/
PROCESS(collect_example, "Contiki Collect View");
AUTOSTART_PROCESSES(&collect_example);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(collect_example, ev, data) {
    PROCESS_BEGIN();

    serial_shell_init();
    shell_blink_init();
    shell_reboot_init();
    shell_rime_init();
    shell_rime_netcmd_init();
    shell_powertrace_init();
    shell_text_init();
    shell_time_init();

#if CONTIKI_TARGET_SKY
    shell_sky_init();
#endif

    shell_collect_view_init();

    PROCESS_END();
}