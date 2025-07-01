package progetto;


simple Storage
{
    parameters:
        int id;
        int numECUs;
        double sendInterval @unit(s);
        int checkInterval;
        int dataLifeTime; 
        
    gates:
        input in;
        output out;
}
