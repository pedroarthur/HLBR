//#define DEBUG

/**
 * Log file keeping functions. 
 *
 * These functions can work in two ways: with a dedicated thread for log file
 * keeping and with no dedicated thread (LOGFILE_THREAD defined or not). 
 * If no dedicated thread is created (LOGFILE_THREAD not defined), the functions
 * here can cause I/O block in the caller thread when writing logs. 
 * If a dedicated thread is created (LOGFILE_THREAD defined), then the message
 * written to a log will actually write the message to a buffer and return to the
 * caller. The thread will take care of flushing the buffers to the respective 
 * log files.
 *
 * In any case, you should call the functions in this order:
 * -# GetLogBuffer() to get a buffer for the message
 * -# Take your time, format and write the message in the buffer
 * -# FlushLogBuffer() to dispatch the buffer for writing in the logs
 */

#include "hlbr.h"
#include "logfile.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern GlobalVars	Globals;

LogFileRec	LogFiles[MAX_LOG_FILES];
int		NumLogFiles;

char		LogBuffers[MAX_LOG_BUFFERS][MAX_LOGBUFFER_SIZE+1];
int		LogBuffersDest[MAX_LOG_BUFFERS]; /**< Index in LogFiles[] for writing this buffer */
int		NumLogBuffers;
#ifdef LOGFILE_THREAD
pthread_mutex_t	LogThreadMutex;	/**< for controlling access to LogBuffers[] */

void InitLogFiles()
{
	int i;

	NumLogFiles = 0;
	NumLogBuffers = 0;
	bzero(LogFiles, sizeof(LogFileRec) * MAX_LOG_FILES);
	for (i=0; i<MAX_LOG_BUFFERS; i++)
		LogBuffersDest[i] = LOGBUFFER_FREE;
}
#endif


/**
 * Creates an entry for the new log file for use.
 * Log files are registered in LogFiles[]. If there is already a log file entry
 * with the same file name, use it instead of creating a new one.
 * @return Index in LogFiles[]
 */
int OpenLogFile(char* name)
{
	int 		i;
	int		f = LOGFILE_NOFILE;
	int*		LockID;
	char		FileName[1024];

	snprintf(FileName, 1024, "%s%s", Globals.LogDir, name);

	pthread_mutex_lock(&LogThreadMutex);

	for (i=0; i<NumLogFiles; i++) {
		if (strcmp(name, LogFiles[i].fname) == 0) {
			//f = &LogFiles[i];
			f = i;
			break;
		}
	}

	if (f == LOGFILE_NOFILE && NumLogFiles < MAX_LOG_FILES) {
		/* allocate new LogFile, update f */
		strncpy(LogFiles[NumLogFiles].fname, name, 1024-1);
#ifdef DEBUG
		printf("Allocating logfile %d: %s (%s) at %x\n", NumLogFiles, LogFiles[NumLogFiles].fname, FileName, &LogFiles[NumLogFiles]);
#endif
		LogFiles[NumLogFiles].fp = fopen(FileName, "a");
		if (!LogFiles[NumLogFiles].fp) {
			fprintf(stderr, "Error opening log file: \"%s\"\n", FileName);
			pthread_mutex_unlock(&LogThreadMutex);
			return f;
		}
		//bzero(&LogFiles[NumLogFiles].FileMutex, sizeof(pthread_mutex_t));
		//LogFiles[NumLogFiles].FileLockID = 0;
		//f = &LogFiles[NumLogFiles++];
		f = NumLogFiles++;
	}

	pthread_mutex_unlock(&LogThreadMutex);

	return f;
}

void* LogBuffer(int Buffer)
{
	return &LogBuffers[Buffer];
}

/**
 * Reserves a buffer, if there is a free one, and returns it.
 * @return Buffer index or LOGBUFFER_NOBUFFER if there was no free buffer 
 */
int GetLogBuffer()
{
	int i, LockID;
	int buf = LOGBUFFER_NOBUFFER;

	if (NumLogBuffers >= MAX_LOG_BUFFERS)
		return buf;

	pthread_mutex_lock(&LogThreadMutex);

	/* yes, check AGAIN, after the mutex lock */
	if (NumLogBuffers >= MAX_LOG_BUFFERS)
		return buf;
  
	for (i=0; i < MAX_LOG_BUFFERS; i++)
		if (LogBuffersDest[i] == LOGBUFFER_FREE) {
			LogBuffersDest[i] = LOGBUFFER_RESERVED;
			NumLogBuffers++;
#ifdef DEBUG
			printf("NumLogBuffers is now %d\n", NumLogBuffers);
#endif
			buf = i;
			break;
		}

	pthread_mutex_unlock(&LogThreadMutex);

	return buf;
}


/**
 * Flush the message previously written in a buffer to a log file.
 * @param Buffer Index in LogBuffers[]
 * @param LogFile Index in LogFiles[]
 * @return TRUE if successful.
 * @see LogMessageGetBuffer()
 */
int FlushLogBuffer(int Buffer, int LogFile)
{
	int i;

	if (Buffer < 0 || Buffer >= MAX_LOG_BUFFERS)
		return FALSE;

#ifdef LOGFILE_THREAD
	LogBuffersDest[Buffer] = LogFile;
#else
	i = strlen(LogBuffers[Buffer]);
	if (fwrite(LogBuffers[Buffer], i, 1, LogFiles[LogFile].fp) == 0)
		fprintf(stderr, "Error writing to log #%d (%s), message: %s\n", 
			LogFile, LogFiles[LogFile].fname, LogBuffers[Buffer]);
	fwrite("\n", 1, 1, LogFiles[LogFile].fp);
	if (fflush(LogFiles[LogFile].fp))
		fprintf(stderr, "Error flushing to log #%d (%s), message: %s\n", 
			LogFile, LogFiles[LogFile].fname, LogBuffers[Buffer]);
#endif

	return TRUE;
}


#ifdef LOGFILE_THREAD
/**
 * Start up a thread to deal with log files.
 */
void* ProcessLogFilesThread(void* v)
{
	int 		i, LockID, len;
	useconds_t	sec;
#define SLEEP_TOTAL	1000000
#define SLEEP_SLICE	250000

	int		ocs;


	sec = SLEEP_TOTAL;

	while (!Globals.Done) {
		if (NumLogBuffers > 0) {
			if (NumLogBuffers == MAX_LOG_BUFFERS)
				printf("All Log Buffers full; flushing them...\n");
#ifdef DEBUG
			printf("ProcessLogFilesThread: Flushing %d message buffers...\n", NumLogBuffers);
#endif
			pthread_mutex_lock(&LogThreadMutex);
			for (i=0; i<MAX_LOG_BUFFERS; i++) {
				if (LogBuffersDest[i] >= 0) {
					//pthread_mutex_lock(&Data->FileMutex);

//				pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ocs);

					len = strlen(LogBuffers[i]);
					fwrite(LogBuffers[i], len, 1, LogFiles[LogBuffersDest[i]].fp);
					if (fwrite("\n", 1, 1, LogFiles[LogBuffersDest[i]].fp) == 0)
						fprintf(stderr, "Error writing to log #%d (%s), message: %s\n", 
							LogBuffersDest[i], LogFiles[LogBuffersDest[i]].fname, LogBuffers[i]);
					if (fflush(LogFiles[LogBuffersDest[i]].fp))
						fprintf(stderr, "Error flushing to log #%d (%s), message: %s\n", 
							LogBuffersDest[i], LogFiles[LogBuffersDest[i]].fname, LogBuffers[i]);

					LogBuffersDest[i] = LOGBUFFER_FREE;
				}

//				pthread_setcancelstate(ocs, NULL);


				//if (Data)
				//	pthread_mutex_unlock(&Data->FileMutex);
			}
			NumLogBuffers = 0;
			pthread_mutex_unlock(&LogThreadMutex);
			if (sec > 0L)
				sec -= SLEEP_SLICE;
		} else {
			/* printf("Sleeping for %ld microsecs\n", sec); */
			usleep(sec);
			if (sec < SLEEP_TOTAL)
				sec += SLEEP_SLICE;
		}
	}

	// Ending program, close all file handlers
	for (i=0; i<MAX_LOG_FILES; i++)
		if (LogFiles[i].fp != NULL)
			fclose(LogFiles[i].fp);

	return NULL;
}
#endif //LOGFILE_THREAD


#ifdef DEBUG
#undef DEBUG
#endif
