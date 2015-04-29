#ifdef USE_MS_ABI
 /* Store registers and move four first input arguments from MS ABI to
  * SYSV ABI.  */
 #define FUNC_ENTRY() \
	pushq %rsi; \
	pushq %rdi; \
	movq %rdx, %rsi; \
	movq %rcx, %rdi; \
	movq %r8, %rdx; \
	movq %r9, %rcx;

 /* Restore registers.  */
 #define FUNC_EXIT() \
	popq %rdi; \
	popq %rsi;
#else
 #define FUNC_ENTRY() /**/
 #define FUNC_EXIT() /**/
#endif
