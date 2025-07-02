package progetto;

simple Infotainment
{
    parameters:
        int id;                   // identificativo univoco della ECU
        int numECUs;              // numero totale di ECU (per scegliere destinazioni)
        double sendInterval @unit(s); // intervallo base per invio richieste (può essere funzione di time)
        int storage1_id;
        int storage2_id;
    gates:
        output out; // verso il Gateway
        input in;   // dalla Gateway
}
