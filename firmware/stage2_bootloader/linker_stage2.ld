MEMORY
{
  FLASH (rx) : ORIGIN = 0x00026000, LENGTH = 0x00028000 - 0x00026000 /* 8 KB */
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x00040000             /* 256 KB */
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.ARM.exidx*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .data : AT(_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + 0x4000; /* 16 KB stack for bootloader */
}
