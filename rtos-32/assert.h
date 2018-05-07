#ifndef RTOS32_ASSERT_H
#define RTOS32_ASSERT_H

#if TARGET_RTOS32
 /* The windows assert function opens a message box. 
  * On RTOS-32 the function is overloaded with a console assert: */
 #define assert(cond) \
 { \
   if((cond) == 0) \
   { \
     printf("FATAL: assert failed: %s:%d\n",__FILE__,__LINE__ ); \
     exit(0); \
   } \
 }
#endif

#endif /* RTOS32_ASSERT_H */