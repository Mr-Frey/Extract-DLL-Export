#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <LIEF/LIEF.hpp>

std::vector<std::string> get_all_files_names_within_folder(std::string folder) {

    std::vector<std::string> DllNames;
    std::string search_path = folder + "/*.dll*";
    WIN32_FIND_DATAA fd;

    HANDLE hFind = FindFirstFileA(search_path.c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {

        do {
            
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

                DllNames.push_back(fd.cFileName);

            }

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }

    return DllNames;
}

int main() {

    std::string folder = "DLL\\";

    std::vector<std::string> DLLNames = get_all_files_names_within_folder(folder);

    std::ofstream data;
    std::ostringstream Ret;
    std::string writeFile;

    try {

        for (int i = 0; i < DLLNames.size(); i++) {

            Ret << "\n=========================================================================================\n"
                << DLLNames[i] << std::endl;
            writeFile = Ret.str();

            std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(folder + DLLNames[i]);

            std::cout << DLLNames[i] << std::endl;

            for (int j = 0; j < pe->exported_functions().size(); j++) {

                Ret << pe->exported_functions()[j].name() << std::endl;

                writeFile = Ret.str();
            }

        }

        data.open(folder + "Exports_das_Dll.txt");

        data << writeFile;

        data.close();

        std::cout << "\n\tSuccess in extracting!" << std::endl;
        
        std::cin.get();

    }

    catch (const std::exception& ex) {

        data.open(folder + "Exports_das_Dll.txt");

        data << writeFile;

        data.close();

        std::cout << "\n\tFail in extracting!" << std::endl;

        std::cin.get();

    }
}