#include <iostream>
#include <cstdint>

void print_diff(int64_t v1, int64_t v2)
{
	char sign = '+';
	int64_t diff1 =  v1 - v2;

	diff1 &= 0x0ffffffff;
	std::cout << "res "<< sign <<"= " <<  std::hex << diff1 << "\t?\t";
	
	sign = '-';
	diff1 =  v2 - v1;
	//diff1 &= 0x0ffffffff;

	std::cout << "res "<< sign <<"= " <<  std::hex << diff1 << "\t?\t";
	std::cout << "res ^= " << std::hex << (v1 ^ v2) << "\n";
}

void print_options(int64_t res1, int64_t res2, int64_t res3)
{
	print_diff(res2 , res1);
	print_diff(res3 , res2);
	//std::cout << "-\n";
	//print_diff(res3 , res1);
	std::cout << "\n---\n";
}

int main ()
{
	std::cout << "Val 0:" << std::endl;
	print_options (0xffffffff4d9ffd7d, 0xffffffff110ee05e, 0xffffffff8faa65e5);
	
	std::cout << "Val 11:" << std::endl;
	print_options (0x24fecdf7e, 0x2dd640b84, 0x5ba64d7f); // t_11
	
	std::cout << "Val 12:" << std::endl;
	print_options (0xffffffff5acb325b, 0xffffffff36292a41, 0xffffffff428de5fe ); // t_12
	
	std::cout << "Val 19:" << std::endl;
	print_options(0xe1d16f8d, 0xe1d1ce49, 0xffffffff63699930); // res_19 ?
	
	std::cout << "Val 20:" << std::endl;
	print_options(0x45782aec, 0x15decf25, 0x3cf9115f); // res_20 ?
	
	std::cout << "Val 23:" << std::endl;
	print_options(0x9dd3c746, 0x9d08a604, 0xfffffffe928db5f5); // res_23 ?
	
	std::cout << "Val 31:" << std::endl;
	print_options(0xfffffffd82cc102d, 0xfffffffd824b6644, 0xffffffff090941cc); // res_31 ?
	return 0;
}

