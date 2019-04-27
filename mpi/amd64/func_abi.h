#include <config.h>

#ifdef __x86_64__
#ifdef HAVE_GCC_ASM_CFI_DIRECTIVES
# define CFI_STARTPROC()            .cfi_startproc
# define CFI_ENDPROC()              .cfi_endproc
# define CFI_ADJUST_CFA_OFFSET(off) .cfi_adjust_cfa_offset off
# define CFI_REL_OFFSET(reg,off)    .cfi_rel_offset reg, off
# define CFI_RESTORE(reg)           .cfi_restore reg

# define CFI_PUSH(reg) \
	CFI_ADJUST_CFA_OFFSET(8); CFI_REL_OFFSET(reg, 0)
# define CFI_POP(reg) \
	CFI_ADJUST_CFA_OFFSET(-8); CFI_RESTORE(reg)
#else
# define CFI_STARTPROC()
# define CFI_ENDPROC()
# define CFI_ADJUST_CFA_OFFSET(off)
# define CFI_REL_OFFSET(reg,off)
# define CFI_RESTORE(reg)

# define CFI_PUSH(reg)
# define CFI_POP(reg)
#endif
#endif

#ifdef USE_MS_ABI
 /* Store registers and move four first input arguments from MS ABI to
  * SYSV ABI.  */
 #define FUNC_ENTRY() \
	CFI_STARTPROC(); \
	pushq %rsi; \
	CFI_PUSH(%rsi); \
	pushq %rdi; \
	CFI_PUSH(%rdi); \
	movq %rdx, %rsi; \
	movq %rcx, %rdi; \
	movq %r8, %rdx; \
	movq %r9, %rcx;

 /* Restore registers.  */
 #define FUNC_EXIT() \
	popq %rdi; \
	CFI_POP(%rdi); \
	popq %rsi; \
	CFI_POP(%rsi); \
	ret; \
	CFI_ENDPROC();
#else
 #define FUNC_ENTRY() \
	CFI_STARTPROC();

 #define FUNC_EXIT() \
	ret; \
	CFI_ENDPROC();
#endif
