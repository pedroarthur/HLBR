#include "decode_ip_defrag.h"
#include "../packets/packet.h"
#include "../engine/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

//#define DEBUG

extern GlobalVars	Globals;

int			IPDecoderID;

Cache*			FragCache;
pthread_mutex_t		FragMutex;
int			FragLockID;

typedef struct defrag_item{
	int		begin;
	int		end;
	int		PacketSlot;
	IPData*		idata;
	int		more;
	char		done;
} DefragItem;

typedef struct defrag_key{
	unsigned short	IPID;
	unsigned int	saddr;
	unsigned int	daddr;
	unsigned char	proto;
} DefragKey;

/************************************************************************
* We have to recalc the IP header checksum
* taken from snort
* TODO: replace with the one from the RFC
*************************************************************************/
unsigned short checksum(unsigned short *b1, unsigned int len1, unsigned short *b2, unsigned int len2) {
	unsigned int sum = 0;

	if(b1 != (unsigned short *)NULL) {
		while(len1 > 1) {
			sum += *((unsigned short *)b1 ++);

			if(sum & 0x80000000) {
				sum = (sum & 0xffff) + (sum >> 16);
			}

			len1 -= 2;
		}

		/* we'll have problems if b2 exists and len1 is odd */
		if(len1) {
			sum += (unsigned short) * (unsigned char*) b1;
		}
	}

	if(b2 != (unsigned short*)NULL) {
		while(len2 > 1) {
			sum += *((unsigned short*)b2 ++);

			if(sum & 0x80000000) {
				sum = (sum & 0xffff) + (sum >> 16);
			}

			len2 -= 2;
		}

		if(len2) {
			sum += (unsigned short) * (unsigned char*) b2;
		}
	}

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (unsigned short) ~sum;
}

/*************************************************************
* Build the packet back together and push it on the pending queue
* TODO: Don't assume ethernet
*************************************************************/
int RebuildPacket(int PacketSlot, DefragItem* Frags, int NumFrags){
	PacketRec	newp;

	IPData*		idata;

	int		i;
	int		flags;
	int		offset;
	int		first_header_len;
	int		offset_to_ip;

	/*allocate enough to hold the packet*/
	newp.LargePacket = TRUE;
	newp.RawPacket = calloc(MAX_PACKET_SIZE,1);

	if (!newp.RawPacket) {
		fprintf (stderr, "Failed to allocate memory for rebuilding the packets fragments\n");
		return FALSE;
	}

	/*create the headers*/
	newp.InterfaceNum = Globals.Packets[Frags[0].PacketSlot].InterfaceNum;
	newp.tv = Globals.Packets[Frags[0].PacketSlot].tv;

	for (i = 0 ; i < NumFrags ; i++){
		if (!GetDataByID(Frags[i].PacketSlot, IPDecoderID, (void**)&idata)){
			printf("1Failed to get IP data in slot %i\n",PacketSlot);
			return FALSE;
		}

		flags = ntohs(idata->Header->frag_off) / 8192;
		offset = ntohs(idata->Header->frag_off) & 0x1FFF;

		if (offset != 0){
			memcpy(newp.RawPacket + (offset * 8) + offset_to_ip + first_header_len,
				Globals.Packets[Frags[i].PacketSlot].RawPacket + (idata->Header->ihl * 4) + offset_to_ip,
				ntohs(idata->Header->tot_len) - (idata->Header->ihl * 4));
#ifdef DEBUG
				printf("This fragment has %i bytes\n",	ntohs(idata->Header->tot_len) - (idata->Header->ihl * 4));
#endif
				newp.PacketLen += ntohs(idata->Header->tot_len) - (idata->Header->ihl * 4);
		} else {
			offset_to_ip = ((int)idata->Header) - ((int)Globals.Packets[Frags[i].PacketSlot].RawPacket);
			first_header_len = idata->Header->ihl*4;
			newp.PacketLen = Globals.Packets[Frags[i].PacketSlot].PacketLen;
			memcpy(newp.RawPacket, Globals.Packets[Frags[i].PacketSlot].RawPacket, newp.PacketLen);
		}
	}

	GetDataByID (PacketSlot, IPDecoderID, (void**)&idata);

	if (!idata) {
		fprintf (stderr, "Failed to get IPData from packet %d\n", PacketSlot);
		return FALSE;
	}

	idata->Header = (IPHdr *)(newp.RawPacket + offset_to_ip);

	idata->Header->frag_off = 0;
	idata->Header->tot_len = htons(newp.PacketLen - 14);

	idata->Header->check = 0;
	idata->Header->check = checksum((unsigned short*)idata->Header,
						idata->Header->ihl * 4,
						NULL, 0);

	Globals.Packets[PacketSlot].InterfaceNum = newp.InterfaceNum;
	Globals.Packets[PacketSlot].RawPacket = newp.RawPacket;
	Globals.Packets[PacketSlot].LargePacket = TRUE;
	Globals.Packets[PacketSlot].PacketLen = newp.PacketLen;
	Globals.Packets[PacketSlot].tv = newp.tv;
	Globals.Packets[PacketSlot].PassRawPacket = TRUE;

	((IPData *)Globals.Packets[PacketSlot].DecoderInfo[IPDecoderID].Data)->Header = idata->Header;
	Globals.Packets[PacketSlot].BeginData = offset_to_ip + idata->Header->ihl * 4;

	#ifdef DEBUG
	for (i=0;i<10;i++){
		printf("Slot %i is in state %i\n",i, Globals.Packets[i].Status);
	}
	#endif

	return TRUE;
}

/*************************************************************
* Sort the Frag Array. Return TRUE if all pieces are present
*************************************************************/
int SortFragArray(DefragItem* Frags, int NumFrags){
	int 	i;
	int	all_done;
	int	found, last, next;

	DEBUGPATH;

	next=0;
	last=FALSE;

	while (1){
		all_done=TRUE;
		found=FALSE;

		for (i=0;i<NumFrags;i++){
			if (Frags[i].done)
				continue;
#ifdef DEBUG
			if (Frags[i].begin < next){
				printf("ERROR! Overlapping Fragements\n");
			}
#endif
			if (Frags[i].begin==next){
				Frags[i].done=TRUE;
				next=Frags[i].end;

				all_done=FALSE;
				found=TRUE;

				if (!Frags[i].more)
					last=TRUE;
#ifdef DEBUG
				printf("More is %i\n",Frags[i].more);
#endif
			}
		}

		if (last)
			break;

		if (all_done)
			break;

		if (!found)
			return FALSE;
	}

	if (!last) {
#ifdef DEBUG
		printf ("Some more frags are missing\n");
#endif
		return FALSE;
	} else {
		int j, val;
		int gap = 1;
#ifdef DEBUG
		printf("We have all the parts\n");
#endif
		/* So, let's easy the job of the defrager... */
		do
			gap = 3 * gap + 1;
		while (gap < NumFrags);

		do {
			gap /= 3;

			for (i = gap ; i < NumFrags ; i++) {
				val = Frags[i].begin;

				for (j = i - gap ; j >= 0 && val < Frags[j].begin ; j -= gap)
					Frags[j + gap].begin = Frags[j].begin;

				Frags[j + gap].begin = val;
			}
		} while (gap > 1);
	}

	return TRUE;
}

/***************************************
* Reassemble fragmented ip packets
****************************************/
void* DecodeIPDefrag(int PacketSlot){
	CacheItems*		CI;
	IPDefragData*		data = NULL;
	IPData*			idata;
	int			flags;
	int			offset;
	DefragKey		Key;

	PacketRec*		ThisPacket;
	DefragItem		Frags[128];
	int			NumFrags;
	int			i;

	PacketRec*		p;

	DEBUGPATH;

#ifdef DEBUG
	printf("----------------------------\n");
	printf("Defragmenting IP\n");
#endif

	pthread_mutex_lock(&FragMutex);
	CacheTimeout(FragCache, time(NULL));
	pthread_mutex_unlock(&FragMutex);

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&idata)){
		printf("Failed to get ip header data\n");
		return NULL;
	}

	flags = ntohs(idata->Header->frag_off) / 8192;
	offset = ntohs(idata->Header->frag_off) & 0x1FFF;

	if ((offset > 0) || (flags & FRAG_FLAG_MORE)){
#ifdef DEBUG
		printf("This is a fragment\n");

		if (offset == 0){
			printf("This is the first Fragment\n");
		}else{
			printf("Fragment at offset %i\n",offset * 8);
			if (flags & FRAG_FLAG_MORE){
				printf("More Fragments\n");
			}else{
				printf("No More Fragments\n");
			}
		}
#endif
		p->PassRawPacket = FALSE;

		Key.IPID = ntohs(idata->Header->id);
		Key.saddr = idata->Header->saddr;
		Key.daddr = idata->Header->daddr;
		Key.proto = idata->Header->protocol;

#ifdef DEBUG
		printf("ID is %u\n",ntohs(idata->Header->id));
		printf("Proto is %u\n",idata->Header->protocol);
#endif
		/*check to see if we have all the pieces*/
		pthread_mutex_lock(&FragMutex);

		CI = CacheGet(FragCache, (unsigned char*)&Key, sizeof(Key), p->tv.tv_sec);
		NumFrags = 0;

		if (CI){
			Frags[0].begin = (ntohs(idata->Header->frag_off) & 0x1FFF) * 8;
			Frags[0].end = Frags[0].begin + ntohs(idata->Header->tot_len) - (idata->Header->ihl*4);
			Frags[0].PacketSlot = PacketSlot;
			Frags[0].done = FALSE;
			Frags[0].more = ntohs(idata->Header->frag_off) / 8192;

			/*do it this way so the compiler optimization doesn't kill it*/
			if (Frags[0].more & FRAG_FLAG_MORE){
				Frags[0].more = TRUE;
			}else{
				Frags[0].more = FALSE;
			}

			NumFrags = 1;
#ifdef DEBUG
			printf("This frag %i-%i\n",Frags[0].begin, Frags[0].end);
#endif
			for (i=0;i<CI->NumItems;i++){
				ThisPacket = &Globals.Packets[*(int*)CI->Items[i].Data];

				if (!GetDataByID(ThisPacket->PacketSlot, IPDecoderID, (void**)&Frags[NumFrags].idata)){
					printf("7Failed to get ip header data for the fragment\n");
					break;
				}

				Frags[NumFrags].begin = (ntohs(Frags[NumFrags].idata->Header->frag_off) & 0x1FFF)*8;
				Frags[NumFrags].end = Frags[NumFrags].begin + ntohs(Frags[NumFrags].idata->Header->tot_len) - (Frags[NumFrags].idata->Header->ihl*4);
				Frags[NumFrags].PacketSlot = ThisPacket->PacketSlot;
				Frags[NumFrags].done = FALSE;
				Frags[NumFrags].more = ntohs(Frags[NumFrags].idata->Header->frag_off) / 8192;

				/*do it this way so the compiler optimization doesn't kill it*/
				if (Frags[NumFrags].more & FRAG_FLAG_MORE){
					Frags[NumFrags].more=TRUE;
				}else{
					Frags[NumFrags].more=FALSE;
				}

				NumFrags++;
			}

			if (!SortFragArray(Frags, NumFrags)){
				/*send this packet off to the cache*/
				/*to wait for the rest of the pieces*/
#ifdef DEBUG
				printf("Adding slot %i\n",PacketSlot);
#endif
				CacheAdd(FragCache, (unsigned char*)&Key, sizeof(DefragKey), (unsigned char*)&PacketSlot, sizeof(int), Globals.Packets[PacketSlot].tv.tv_sec);
				Globals.Packets[PacketSlot].SaveCount++;
#ifdef DEBUG
				printf("Still more packets\n");
#endif
			}else{
				/*tell the engine we're done with these packets*/
				if (!RebuildPacket(PacketSlot, Frags, NumFrags)) {
					CacheDelKey(FragCache, (unsigned char*)&Key, sizeof(DefragKey), Globals.Packets[PacketSlot].tv.tv_sec);
					pthread_mutex_unlock(&FragMutex);

					return NULL;
				}
#ifdef DEBUG
				printf("Packet was rebuilt\n");
#endif
				data=calloc(sizeof(IPDefragData),1);
				if (!data){
					pthread_mutex_unlock(&FragMutex);
					return NULL;
				}

				data->IsRebuilt=TRUE;

				CacheDelKey(FragCache, (unsigned char*)&Key, sizeof(DefragKey), Globals.Packets[PacketSlot].tv.tv_sec);
			}
		}else{
			CacheAdd(FragCache, (unsigned char*)&Key, sizeof(DefragKey), (unsigned char*)&PacketSlot, sizeof(int), Globals.Packets[PacketSlot].tv.tv_sec);
			Globals.Packets[PacketSlot].SaveCount++;
#ifdef DEBUG
			printf("First piece\n");
#endif
		}

		pthread_mutex_unlock(&FragMutex);
	}else{
		data=calloc(sizeof(IPDefragData),1);
		data->IsRebuilt=FALSE;
	}

	return data;
}

void IPDefragCacheFreeFunction (void *pointer) {
	int PacketSlot = *(int*)pointer;

	DEBUGPATH;

	if (Globals.Packets[PacketSlot].LargePacket)
		return;

	#ifdef DEBUG
	printf("Returning slot %i\n", PacketSlot);
	#endif

	Globals.Packets[PacketSlot].SaveCount--;

	#ifdef DEBUG
	printf("SaveCount is now %i\n",Globals.Packets[PacketSlot].SaveCount);
	#endif

	ReturnEmptyPacket(*(int*)pointer);
}

int InitDecoderIPDefrag(){
	int DecoderID;

	DEBUGPATH;

	if ((DecoderID=CreateDecoder("IPDefrag")) == DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate IP Defrag Decoder\n");
#endif
		return FALSE;
	}

	Globals.Decoders[DecoderID].DecodeFunc = DecodeIPDefrag;
	Globals.Decoders[DecoderID].Free = free;

	IPDecoderID = GetDecoderByName("IP");

	if (!DecoderAddDecoder(IPDecoderID, DecoderID)){
		printf("Failed to Bind IP Defrag Decoder to IP Decoder\n");
		return FALSE;
	}

	FragCache = InitCache(FRAG_TIMEOUT, IPDefragCacheFreeFunction);

	return TRUE;
}
