/* This file is part of the libopencm3 project.
 *
 * It was generated by the irq2nvic_h script from ./include/libopencm3/swm050/irq.json
 */

#ifndef LIBOPENCM3_SWM050_NVIC_H
#define LIBOPENCM3_SWM050_NVIC_H

#include <libopencm3/cm3/nvic.h>

/** @defgroup CM3_nvic_defines_irqs User interrupts for SWM050 series
    @ingroup CM3_nvic_defines

    @{*/

#define NVIC_TIMER_SE0_IRQ 0
#define NVIC_TIMER_SE1_IRQ 1
#define NVIC_WDT_IRQ 2
#define NVIC_CP_IRQ 3
#define NVIC_GPIOA0_IRQ 4
#define NVIC_GPIOA1_IRQ 5
#define NVIC_GPIOA2_IRQ 6
#define NVIC_GPIOA3_IRQ 7
#define NVIC_GPIOA4_IRQ 8
#define NVIC_GPIOA5_IRQ 9
#define NVIC_GPIOA6_IRQ 10
#define NVIC_GPIOA7_IRQ 11
#define NVIC_GPIOA8_IRQ 12
#define NVIC_GPIOA9_IRQ 13

#define NVIC_IRQ_COUNT 14

/**@}*/

/** @defgroup CM3_nvic_isrprototypes_SWM050 User interrupt service routines (ISR) prototypes for SWM050 series
    @ingroup CM3_nvic_isrprototypes

    @{*/

BEGIN_DECLS

void timer_se0_isr(void);
void timer_se1_isr(void);
void wdt_isr(void);
void cp_isr(void);
void gpioa0_isr(void);
void gpioa1_isr(void);
void gpioa2_isr(void);
void gpioa3_isr(void);
void gpioa4_isr(void);
void gpioa5_isr(void);
void gpioa6_isr(void);
void gpioa7_isr(void);
void gpioa8_isr(void);
void gpioa9_isr(void);

END_DECLS

/**@}*/

#endif /* LIBOPENCM3_SWM050_NVIC_H */