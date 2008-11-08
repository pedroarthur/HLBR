#ifndef _LOGFILE_H_
#define _LOGFILE_H_

#ifdef LOGFILE_THREAD
#ifndef HAS_THREADS	/* Won't create log file keeping thread if isn't in threaded mode */
#define LOGFILE_THREAD_NO
#undef LOGFILE_THREAD
#endif
#endif

#define LOGBUFFER_NOBUFFER	-1  /**< No free buffer found */
#define LOGFILE_NOFILE		-1  /**< No LogFile was allocated */
#define LOGBUFFER_FREE		-2  /**< Buffer is free for take */
#define LOGBUFFER_RESERVED	-3  /**< Buffer is reserved but not finished writing yet */

#define MAX_LOG_FILES		16
#define MAX_LOG_BUFFERS		(MAX_LOG_FILES*2)
#define MAX_LOGBUFFER_SIZE	4096

/**
 * Struct used to keep names/handlers/etc of log files.
 * This is mainly used (now) by action alert file.
 */
typedef struct log_file_rec {
	char	fname[1024];
	FILE*	fp;
//#ifndef LOGFILE_THREAD
//#ifdef HASTHREADS
//	pthread_mutex_t		FileMutex;
//  	int			FileLockID;
//#endif
//#endif
} LogFileRec;

void InitLogFiles();
int OpenLogFile(char* name);
void* LogBuffer(int Buffer);
int GetLogBuffer();
int FlushLogBuffer(int Buffer, int LogFile);
void* ProcessLogFilesThread(void* v);

#endif /* _LOGFILE_H_ */
