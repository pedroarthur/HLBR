/*********************************************
* This is an example of how to pull data out
* of the packet.  It may not compile
**********************************************/

extern GlobalVars	Globals;

int TCPDecoderID;
int IPDecoderID;

int AlertSampleMessage(char* Message, void* Data){
#ifdef DEBUGPATH
	printf("In AlertConsoleMessage\n");
#endif

	printf("%s\n",Message);
	
	return TRUE;
}

int AlertSampleAction(int RuleNum, int PacketSlot, void* Data){
	char		Buff[1024];
	PacketRec*	p;
	IPData*		IData;
	TCPData*	TData;
	
	p=&Globals.Packets[PacketSlot];

	if (!GetDataByID(PacketSlot, IPDecoderID, (void**)&IData)){
		printf("This isn't an IP packet\n");
		return TRUE;
	}
	
	printf ("IP Packet:\n");
	printf ("version        %u\n", IData->Header->version);
	printf ("header length  %u\n", IData->Header->ihl*5);
	printf ("tos            %u\n", IData->Header->tos);
	printf ("total len      %u\n", ntohs(IData->Header->tot_len));
	printf ("id             %u\n", ntohs(IData->Header->id));
	printf ("frag offset    %u\n", ntohs(IData->Header->frag_off));
	printf ("Time to Live   %u\n", IData->Header->ttl;
	printf ("IP Protocol    %u\n", IData->Header->protocol;
	printf ("checksum       %u\n", ntohs(IData->Header->check));
	printf ("Source Addr    %s\n", inet_ntoa(IData->Header->saddr));
	printf ("Source Addr    %s\n", inet_ntoa(IData->Header->daddr));
		
	if (!GetDataByID(PacketSlot, TCPDecoderID, (void**)&TData)){
		printf("This isn't an TCP packet\n");
		return TRUE;
	}
	
	printf ("source port    %u\n", ntohs(TData->Header->source));
	printf ("dest port      %u\n", ntohs(TData->Header->dest));
	printf ("seq number     %u\n", ntohl(TData->Header->seq));
	printf ("ackn number    %u\n", ntohl(TData->Header->ack_seq));
	printf ("Fin            %u\n", TData->Header->fin);
	printf ("Syn            %u\n", TData->Header->syn);
	printf ("Rst            %u\n", TData->Header->rst);
	printf ("Psh            %u\n", TData->Header->psh);
	printf ("Ack            %u\n", TData->Header->ack);
	printf ("Urg            %u\n", TData->Header->urg);
	printf ("Ece            %u\n", TData->Header->ece);
	printf ("Cwr            %u\n", TData->Header->cwr);
	printf ("Window         %u\n", ntohs(TData->Header->window));
	printf ("checksum       %u\n", ntohs(TData->Header->check));
	printf ("urgent         %u\n", ntohs(TData->Header->urg_ptr));
	
	return TRUE;
}

int InitActionAlertSample(){
	int ActionID;

	ActionID=CreateAction("alert sample");
	if (ActionID==ACTION_NONE){
#ifdef DEBUG
		printf("Couldn't allocation action alert sample\n");
#endif	
		return FALSE;
	}
	
	Globals.ActionItems[ActionID].ActionFunc=AlertSampleAction;
	Globals.ActionItems[ActionID].MessageFunc=AlertSampleMessage;
	
	IPDecoderID=GetDecoderByName("IP");
	TCPDecoderID=GetDecoderByName("TCP");

	return TRUE;
}
