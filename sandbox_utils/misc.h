#ifdef DEBUG
#define PRINT_ERROR(str) \
    perror(str)
#else
#define PRINT_ERROR(str) ;
#endif