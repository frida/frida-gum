#ifdef __APPLE__
# define GUM_PHARO_SYMBOL(name) _ ## name
# define GUM_PHARO_RODATA .section __TEXT,__const
#else
# define GUM_PHARO_SYMBOL(name) name
# define GUM_PHARO_RODATA .section .rodata
#endif

    GUM_PHARO_RODATA

    .globl GUM_PHARO_SYMBOL (gum_pharo_image_data)
    .p2align 4
GUM_PHARO_SYMBOL (gum_pharo_image_data):
    .incbin GUM_PHARO_IMAGE_PATH
GUM_PHARO_SYMBOL (gum_pharo_image_end):

    .globl GUM_PHARO_SYMBOL (gum_pharo_image_size)
    .p2align 3
GUM_PHARO_SYMBOL (gum_pharo_image_size):
    .quad GUM_PHARO_SYMBOL (gum_pharo_image_end) - GUM_PHARO_SYMBOL (gum_pharo_image_data)
