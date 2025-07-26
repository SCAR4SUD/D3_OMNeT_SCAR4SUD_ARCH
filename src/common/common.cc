#include "common.h"

void handle_errors(const std::string& context) {
    std::cerr << "[Errore] " << context << std::endl;
    ERR_print_errors_fp(stderr);
    //exit(1);
}


