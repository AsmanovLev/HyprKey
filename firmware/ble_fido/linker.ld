MEMORY
{
  FLASH (rx) : ORIGIN = 0x00026000, LENGTH = 0x000ED000 - 0x00026000
  RAM (rwx)  : ORIGIN = 0x20003600, LENGTH = 0x40000 - 0x3600
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

  .noinit (NOLOAD) :
  {
    . = ALIGN(4);
    *(.noinit*)
    . = ALIGN(4);
  } > RAM

  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
