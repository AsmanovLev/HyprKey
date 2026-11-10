#ifndef USB_COMPOSITE_H
#define USB_COMPOSITE_H

#include <stdint.h>
#include <stdbool.h>

void usb_composite_init(void);
void usb_composite_poll(void);
void usb_composite_stop(void);
bool usb_composite_is_configured(void);
void usb_composite_type_string(const char *str);

#endif /* USB_COMPOSITE_H */
