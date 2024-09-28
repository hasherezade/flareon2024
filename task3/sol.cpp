#include <iostream>

struct CRC32_s
{
	void generate_table(uint32_t(&table)[256])
	{
		uint32_t polynomial = 0xEDB88320;
		for (uint32_t i = 0; i < 256; i++)
		{
			uint32_t c = i;
			for (size_t j = 0; j < 8; j++)
			{
				if (c & 1) {
					c = polynomial ^ (c >> 1);
				}
				else {
					c >>= 1;
				}
			}
			table[i] = c;
		}
	}

	uint32_t update(uint32_t(&table)[256], uint32_t initial, const void* buf, size_t len)
	{
		uint32_t c = initial ^ 0xFFFFFFFF;
		const uint8_t* u = static_cast<const uint8_t*>(buf);
		for (size_t i = 0; i < len; ++i)
		{
			c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
		}
		return c ^ 0xFFFFFFFF;
	}
};

class CRC32
{
private:
	uint32_t table[256];
	CRC32_s crc32_s;
	uint32_t initial;
public:
	CRC32()
		: initial(0)
	{
		crc32_s.generate_table(table);
	}

	void Update(const uint8_t * buf, size_t len)
	{
		initial = crc32_s.update(table, initial, (const void *)buf, len);
	}

	uint32_t GetValue() const
	{
		return initial;
	}
};


bool search_checks(char x34, char x35, uint32_t checks)
{
	CRC32 c;
	uint8_t buf[2] = {x34, x35}; 
	c.Update(buf, 2);
	if (c.GetValue() == checks) return true;
	return false;
}

bool find_and_fill(char *buf, size_t pos, uint32_t checks)
{
	for (char a = 0x20; a < 0x7e; a++) {
		for (char b = 0x20; b < 0x7e; b++) {
			if (search_checks(a, b, checks)) {
				buf[pos] = a;
				buf[pos+1] = b;
				printf("Found: %x %x = %c %c\n", a, b, a,b);
			}
		}
	}
}

int main(int argc, char *argv)
{
	bool verbose = false;
	if (argc >= 2) {
		verbose = true;
	}
	
	char buf[85] = { 0 };
	
	buf[32] = 'u';
	buf[33] = 'l';

	buf[0] = 'r';
	buf[1] = 'u';
	buf[2] = 'l';
	buf[76] = 'i';
	buf[77] = 'o';

	buf[50] = '3';
	buf[51] = 'A';

	buf[56] = 'f';
	buf[57] = 'l';
	buf[58] = 'a';
	buf[63] = 'n';
	buf[64] = '.';
	buf[65] = 'c';
	buf[45] = 9 ^ 104;
	buf[36] = 72 - 4;
	*(uint32_t*)((uint64_t)buf + 3) = uint32_t(298697263) ^ uint32_t(2108416586);
	*(uint32_t*)((uint64_t)buf + 52) = uint32_t(425706662) ^ uint32_t(1495724241);
	*(uint32_t*)((uint64_t)buf + 66) = uint32_t(310886682) ^ uint32_t(849718389);
	*(uint32_t*)((uint64_t)buf + 10) = uint32_t(2448764514) - uint32_t(383041523);
	*(uint32_t*)((uint64_t)buf + 17) = uint32_t(323157430) + uint32_t(1412131772);

	*(uint32_t*)((uint64_t)buf + 59) = uint32_t(512952669) ^ uint32_t(1908304943);
	*(uint32_t*)((uint64_t)buf + 28) = uint32_t(419186860) + uint32_t(959764852);

	*(uint32_t*)((uint64_t)buf + 37) =  uint32_t(1228527996) -uint32_t(367943707);
	*(uint32_t*)((uint64_t)buf + 22) = uint32_t(372102464) ^ uint32_t(1879700858) ;
	*(uint32_t*)((uint64_t)buf + 46) = uint32_t(412326611) + uint32_t(1503714457) ;

	*(uint32_t*)((uint64_t)buf + 70) = uint32_t(2034162376) - uint32_t(349203301);
	*(uint32_t*)((uint64_t)buf + 80) = uint32_t(473886976) + uint32_t(69677856) ;

	*(uint32_t*)((uint64_t)buf + 41) = uint32_t(1699114335) - uint32_t(404880684);
	
	
	printf("Searching...\n");
	find_and_fill(buf, 34, 0x5888fc1b);
	find_and_fill(buf, 8, 0x61089c5c);
	find_and_fill(buf, 63, 0x66715919);
	find_and_fill(buf, 78, 0x7cab8d64);
	
	for (size_t i = 0; i < 85; i++) {
		if (!buf[i]) {
			if (verbose) printf("[%d] = ?\n", i);
			else printf("_");
			continue;
		}
		uint8_t val = buf[i];
		if (verbose) printf("[%d] = %c = %x\n", i, val, val);
		else printf("%c", val);
	}

	return 0;
}
