#include "decode_ip_defrag.h"
#include "../packets/packet.h"
#include "../engine/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

//#define DEBUG

/**********************************************
* Pretty much this whole thing needs to get
* rewritten. I was using it as a test 
* harness for the packet caching system.
***********************************************/

extern GlobalVars	Globals;

int				IPDecoderID;
Cache*			FragCache;
pthread_mutex_t	FragMutex;
int				FragLockID;

struct defrag_item{
	int				begin;
	int				end;
	int				PacketSlot;
	IPData*			idata;
	int				more;
	char			done;
};

/************************************************************************
* We have to recalc the IP header checksum
* taken from snort
* TODO: replace with the one from the RFC
*************************************************************************/
unsigned short checksum(unsigned short *b1, unsigned int len1, unsigned short *b2, unsigned int len2)
{
    unsigned int sum = 0;

    if(b1 != (unsigned short *)NULL) 
    {
        while(len1 > 1) 
        {
            sum += *((unsigned short *)b1 ++);

            if(sum & 0x80000000)
            {
                sum = (sum & 0xffff) + (sum >> 16);
            }

            len1 -= 2;
        }
    
        /* we'll have problems if b2 exists and len1 is odd */
        if(len1)
        {
           sum += (unsigned short) * (unsigned char*) b1;
        }
    }

    if(b2 != (unsigned short*)NULL) 
    {
        while(len2 > 1) 
        {
            sum += *((unsigned short*)b2 ++);

            if(sum & 0x80000000)
            {
                sum = (sum & 0xffff) + (sum >> 16);
            }

            len2 -= 2;
        }

        if(len2)
        {
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
int RebuildPacket(struct defrag_item* Frags, int NumFrags){
	PacketRec*	newp;
	IPData*		idata;
	int			i;
	int			flags;
	int			offset;
	int			first_header_len;
	int			offset_to_ip;
	int			PacketSlot;
	
	/*stick together the packet and put it on the pending queue*/
	PacketSlot=GetEmptyPacket();
	
	newp=&Globals.Packets[PacketSlot];
	
	/*allocate enough to hold the packet*/
	newp->LargePacket=TRUE;
	newp->RawPacket=calloc(MAX_PACKET_SIZE,1);
	
	/*create the headers*/
	newp->InterfaceNum=Globals.Packets[Frags[0].PacketSlot].InterfaceNum;
	newp->tv=Globals.Packets[Frags[0].PacketSlot].tv;
	
	for (i=0;i<NumFrags;i++){
		if (!GetDataByID(Frags[i].PacketSlot, IPDecoderID, (void**)&idata)){
			printf("1Failed to get IP data in slot %i\n",PacketSlot);
			return FALSE;
		}
	
		flags=ntohs(idata->Header->frag_off) / 8192;
		offset=ntohs(idata->Header->frag_off) & 0x1FFF;
		
		if (offset==0){
			offset_to_ip=((int)idata->Header) - ((int)Globals.Packets[Frags[i].PacketSlot].RawPacket);
			first_header_len=idata->Header->ihl*4;
			newp->PacketLen=Globals.Packets[Frags[i].PacketSlot].PacketLen;
			memcpy(newp->RawPacket, Globals.Packets[Frags[i].PacketSlot].RawPacket, newp->PacketLen);
		}
	}
	
	for (i=0;i<NumFrags;i++){
		if (!GetDataByID(Frags[i].PacketSlot, IPDecoderID, (void**)&idata)){
			printf("2Failed to get IP data\n");
			return FALSE;
		}
	
		flags=ntohs(idata->Header->frag_off) / 8192;
		offset=ntohs(idata->Header->frag_off) & 0x1FFF;
		
		if (offset!=0){
			memcpy(newp->RawPacket+(offset*8)+offset_to_ip+first_header_len,
				Globals.Packets[Frags[i].PacketSlot].RawPacket+(idata->Header->ihl*4)+offset_to_ip,
				ntohs(idata->Header->tot_len)-(idata->Header->ihl*4));
#ifdef DEBUG				
			printf("This fragment has %i bytes\n",	ntohs(idata->Header->tot_len)-(idata->Header->ihl*4));
#endif			
			newp->PacketLen+=ntohs(idata->Header->tot_len)-(idata->Header->ihl*4);
		}
	}

	for (i=0;i<NumFrags;i++){
		if (!GetDataByID(Frags[i].PacketSlot, IPDecoderID, (void**)&idata)){
			printf("3Failed to get IP data\n");
			return FALSE;
		}
	
		flags=ntohs(idata->Header->frag_off) / 8192;
		offset=ntohs(idata->Header->frag_off) & 0x1FFF;
		
		if (offset==0){
			((struct ip_header*)(newp->RawPacket+offset_to_ip))->frag_off=0;
			((struct ip_header*)(newp->RawPacket+offset_to_ip))->tot_len=htons(newp->PacketLen-14);
			((struct ip_header*)(newp->RawPacket+offset_to_ip))->check=0;
			((struct ip_header*)(newp->RawPacket+offset_to_ip))->check=checksum(
				(unsigned short*)(newp->RawPacket+offset_to_ip),
				((struct ip_header*)(newp->RawPacket+offset_to_ip))->ihl*4,
				NULL,
				0
				);
		}
	}

#ifdef DEBUG	
	for (i=0;i<10;i++){
		printf("Slot %i is in state %i\n",i, Globals.Packets[i].Status);
	}
#endif	
		
	return AddPacketToPending(PacketSlot);
}

/*************************************************************
* Sort the Frag Array. Return TRUE if all pieces are present
* TODO: Do an alert on overlapping fragments;
*************************************************************/
int SortFragArray(struct defrag_item* Frags, int NumFrags){
	int 		i;
	int			next;
	int			all_done;
	int			found;
	int			last;
	
#ifdef DEBUGPATH
	printf("In SortFragArray\n");
#endif

	next=0;
	last=FALSE;
	while (1){
		all_done=TRUE;
		found=FALSE;
		for (i=0;i<NumFrags;i++){
			if (!Frags[i].done){
				if (Frags[i].begin < next){
					printf("ERROR! Overlapping Fragements\n");
//					return FALSE;
				}
				if (Frags[i].begin==next){
					Frags[i].done=TRUE;
					next=Frags[i].end;
					all_done=FALSE;
					found=TRUE;
#ifdef DEBUG					
					printf("More is %i\n",Frags[i].more);
#endif					
					if (!Frags[i].more) last=TRUE;
				}
			}
		}
		if (last) break;
		if (all_done) break;
		if (!found) return FALSE;
	}
	
	if (!last) return FALSE;

#ifdef DEBUG	
	printf("We have all the parts\n");
#endif	
	
	return TRUE;
}

/***************************************
* Reassemble fragmented ip packets
****************************************/
void* DecodeIPDefrag(int PacketSlot){
	struct defrag_key{
		unsigned short	IPID;
		unsigned int	saddr;
		unsigned int	daddr;
		unsigned char	proto;
	};

	CacheItems*			CI;	
	IPDefragData*		data=NULL;
	IPData*				idata;
	int					flags;
	int					offset;
	struct defrag_key	Key;
	
	PacketRec*			ThisPacket;
	struct defrag_item	Frags[128];
	int					NumFrags;
	int					i;
	
	PacketRec*			p;
	
#ifdef DEBUGPATH
	printf("In DecodeIPDefrag\n");
#endif

#ifdef DEBUG
	printf("----------------------------\n");
	printf("Defragmenting IP\n");
#endif

	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&idata)){
		printf("Failed to get ip header data\n");
		return NULL;
	}
	
	flags=ntohs(idata->Header->frag_off) / 8192;
	offset=ntohs(idata->Header->frag_off) & 0x1FFF;
	
	if ( (offset>0) || (flags & FRAG_FLAG_MORE) ){
#ifdef DEBUG	
		printf("This is a fragment\n");
#endif	 
		p->PassRawPacket=FALSE;
#ifdef DEBUG		
		if (offset==0){
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

		Key.IPID=ntohs(idata->Header->id);
		Key.saddr=idata->Header->saddr;
		Key.daddr=idata->Header->daddr;
		Key.proto=idata->Header->protocol;
		
		printf("ID is %u\n",ntohs(idata->Header->id));
		printf("Proto is %u\n",idata->Header->protocol);
		
		/*check to see if we have all the pieces*/
		hogwash_mutex_lock(&FragMutex, FRAG_LOCK_1, &FragLockID);
		CI=CacheGet(FragCache, (unsigned char*)&Key, sizeof(Key), p->tv.tv_sec);
		NumFrags=0;
		if (CI){
			Frags[0].begin=(ntohs(idata->Header->frag_off) & 0x1FFF)*8;
			Frags[0].end=Frags[0].begin+ntohs(idata->Header->tot_len)-(idata->Header->ihl*4);
			Frags[0].PacketSlot=PacketSlot;
			Frags[0].done=FALSE;
			Frags[0].more=ntohs(idata->Header->frag_off) / 8192;
			/*do it this way so the compiler optimization doesn't kill it*/
			if (Frags[0].more & FRAG_FLAG_MORE){
				Frags[0].more=TRUE;
			}else{
				Frags[0].more=FALSE;
			}				
			NumFrags=1;
#ifdef DEBUG			
			printf("This frag %i-%i\n",Frags[0].begin, Frags[0].end);
#endif			
		
			for (i=0;i<CI->NumItems;i++){
				ThisPacket=&Globals.Packets[*(int*)CI->Items[i].Data];
				if (!GetDataByID(ThisPacket->PacketSlot, IPDecoderID, (void**)&Frags[NumFrags].idata)){
					printf("7Failed to get ip header data for the fragment\n");
					break;
				}
				Frags[NumFrags].begin=(ntohs(Frags[NumFrags].idata->Header->frag_off) & 0x1FFF)*8;
				Frags[NumFrags].end=Frags[NumFrags].begin+ntohs(Frags[NumFrags].idata->Header->tot_len)-(Frags[NumFrags].idata->Header->ihl*4);
				Frags[NumFrags].PacketSlot=ThisPacket->PacketSlot;
				Frags[NumFrags].done=FALSE;
				Frags[NumFrags].more=ntohs(Frags[NumFrags].idata->Header->frag_off) / 8192;
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
				printf("Adding slot %i\n",PacketSlot);				
				CacheAdd(FragCache, (unsigned char*)&Key, sizeof(struct defrag_key), (unsigned char*)&PacketSlot, sizeof(int), Globals.Packets[PacketSlot].tv.tv_sec);
				Globals.Packets[PacketSlot].SaveCount++;
#ifdef DEBUG
				printf("Still more packets\n");
#endif								
			}else{
				/*tell the engine we're done with these packets*/
				RebuildPacket(Frags, NumFrags);
				for (i=0;i<CI->NumItems;i++){
					printf("Returning slot %i\n",*(int*)CI->Items[i].Data);
					Globals.Packets[*(int*)CI->Items[i].Data].SaveCount--;
					printf("SaveCount is now %i\n",Globals.Packets[*(int*)CI->Items[i].Data].SaveCount);
					ReturnEmptyPacket(*(int*)CI->Items[i].Data);
				}
				CacheDelKey(FragCache, (unsigned char*)&Key, sizeof(struct defrag_key), Globals.Packets[PacketSlot].tv.tv_sec);
#ifdef DEBUG
				printf("Packet was rebuilt\n");
#endif				
			}
		}else{	
			printf("Adding slot %i\n",PacketSlot);		
			CacheAdd(FragCache, (unsigned char*)&Key, sizeof(struct defrag_key), (unsigned char*)&PacketSlot, sizeof(int), Globals.Packets[PacketSlot].tv.tv_sec);
			Globals.Packets[PacketSlot].SaveCount++;
#ifdef DEBUG
			printf("First piece\n");
#endif											
		}
		hogwash_mutex_unlock(&FragMutex);
	}else{
		data=calloc(sizeof(IPDefragData),1);
		data->IsRebuilt=FALSE;
	}
			
	return data;
}

/*************************************
* Set up the decoder
*************************************/
int InitDecoderIPDefrag(){
	int DecoderID;

#ifdef DEBUGPATH
	printf("In InitDecoderIPDefrag\n");
#endif

	if ((DecoderID=CreateDecoder("IPDefrag"))==DECODER_NONE){
#ifdef DEBUG
		printf("Couldn't Allocate IP Defrag Decoder\n");
#endif	
		return FALSE;
	}
	
	Globals.Decoders[DecoderID].DecodeFunc=DecodeIPDefrag;
	if (!DecoderAddDecoder(GetDecoderByName("IP"), DecoderID)){
		printf("Failed to Bind IP Defrag Decoder to IP Decoder\n");
		return FALSE;
	}

	IPDecoderID=GetDecoderByName("IP");
	
	FragCache=InitCache(FRAG_TIMEOUT);

	return TRUE;
}
