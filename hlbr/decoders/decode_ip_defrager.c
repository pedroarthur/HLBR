#include "decode_ip_defrager.h"
#include "../packets/packet.h"
#include "../engine/hlbrlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

extern GlobalVars Globals;

int IPDecoderID;

HashTable *FragedPackets;

typedef struct {
	int begin;
	int end;
	int packetSlot;

	int hasMore;
	char itsDone;

	IPData *packetData;
} DefragedItem;

typedef struct {
	unsigned short id;
	unsigned int srcAddr;
	unsigned int dstAddr;
	unsigned char protocol;
} FragmentKey;

unsigned short checksum (unsigned short *start, unsigned int len) {
	unsigned int sum = 0;

	if (start == NULL)
		return sum;

	while (len > 1) {
		sum += *((unsigned short *)start++);

		if (sum & 0x80000000 != 0)
			sum = (sum & 0xFFFF) + (sum >> 16);

		len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (unsigned short) ~sum;
}

int SortFragments(Queue *fragments) {
	return 0;
}

int RebuildPacket(Queue *fragments, int PacketSlot) {
	return -1;
}

void *DecodeIPDefrager (int PacketSlot) {
	FragmentKey
		fKey;

	IPDefragerData
		*data = NULL;

	IPData
		*ipData = NULL;

	int
		flags = 0,
		offset = 0;

	if (GetDataByID(PacketSlot, IPDecoderID, (void**)&ipData) == 0)
		return NULL;

	data = (IPDefragerData*) calloc (1, sizeof(IPDefragerData));

	if (data == NULL)
		return NULL;

	flags = ntohs(ipData->Header->frag_off) / 8192;
	offset = ntohs(ipData->Header->frag_off) & 0x1FFF;

	if (offset <= 0 && flags & FRAG_FLAG_MORE == 0)
		return data;

	fKey = (FragmentKey) {
		ntohs(ipData->Header->id),
		ipData->Header->saddr,
		ipData->Header->daddr,
		ipData->Header->protocol,
	};

	HashTableTransactionBegin(FragedPackets);

	if (HashTableHasKey(FragedPackets, &fKey) == FALSE) {
		void *r = NULL;
		Queue *q = QueueNew();

		if (q == NULL) {
			free(data);

			HashTableTransactionEnd(FragedPackets);
			return NULL;
		}

		r = HashTableInsert(FragedPackets, &fKey, (void*) q);

		if (r == NULL) {
			free(data);
			free(q);

			HashTableTransactionEnd(FragedPackets);
			return NULL;
		}

		/* TODO: code a destroy handler */
		QueueAddDestroyHandler(q, NULL);
		QueueAddData(q, (void*)PacketSlot);

		Globals.Packets[PacketSlot].PassRawPacket = FALSE;

	} else {
		int rebuildedPacket = 0;

		Queue *fragments = (Queue*) HashTableInsert(FragedPackets, &fKey, NULL);
		QueueAddData(fragments, (void*)PacketSlot);

		/* TODO: completeness verifying function */
		if (SortFragments(fragments) == 0) {
			HashTableTransactionEnd(FragedPackets);
			return data;
		}

		/* TODO: rebuilding function */
		rebuildedPacket = RebuildPacket(fragments, PacketSlot);

		if (rebuildedPacket > -1) {
			data->IsRebuilt = TRUE;
			fragments = (Queue*) HashTableRemove(FragedPackets, &fKey);
			QueueDestroy(fragments);
		}
	}

	HashTableTransactionEnd(FragedPackets);

	return data;
}