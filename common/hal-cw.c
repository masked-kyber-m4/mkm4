#include "pqm4-hal.h"
#include "hal.h"

void hal_setup(const enum clock_mode clock){
  (void) clock;
  platform_init();
  init_uart();
  trigger_setup();
}
void hal_send_str(const char* in){
  while (*in) {
    putch(*(in++));
  }
  putch('\n');
}
uint64_t hal_get_time(void){
  return 0;
}