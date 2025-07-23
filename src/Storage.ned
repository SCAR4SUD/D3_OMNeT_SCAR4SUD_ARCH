package progetto;


simple Storage
{
    parameters:
        int id;
        int numECUs;
        double sendInterval @unit(s);
        int checkInterval;
        int dataLifeTime;
        int clean_files; 
        int storage1_id;
        int storage2_id;
        
    gates:
        input in;
        output out;
}
