//enum DataPrivacy{
//	PRIVATE_DATA = 1;
//	PUBLIC_DATA = 0;
//};
//Inserire un tag per il dato se Anagrafico

message Packet {
    int type;
    int srcId;
    int dstId;
    string data;
    int PrivacyLevel;
}
