#include "acpi.h"

const char acpi_ident[] = "RSD PTR \0";
const uint64 acpi_id = 0x2052545020445352;
char acpi_OEMID[7];

/*@null@*/ struct RSDPDescriptor20 *acpi_probe()
{
	char *tmp;
	struct RSDPDescriptor20 *ret = NULL;
	uint64 offset;
	struct ACPISDTHeader *RSDT;

	printf("acpi_probe: ");

	for(offset = 0xe000; offset < 0xFFFFF; offset+=16)
	{
		tmp = (char *)(0 + offset);

		if(*(uint64 *)tmp == acpi_id) {
			ret = (struct RSDPDescriptor20 *)tmp;
			printf("found at %p", tmp);
			break;
		}
	}

	printf("\n");

	if(ret == NULL) return ret;

	memcpy((char *)&acpi_OEMID, (void *)&ret->OEMID, 6);
	acpi_OEMID[6] = '\0';

	printf("acpi_probe: oem='%s' rev=%u rsdt=%x",
			acpi_OEMID,
			(uint32)ret->Revision,
			ret->RsdtAddress);
	if((uint32)ret->Revision >= 2) {
		printf("len=%x xsdt=%lx", 
				ret->Length,
				ret->XsdtAddress);
	}
	printf("\n");

	RSDT = (struct ACPISDTHeader *)(uint64)ret->RsdtAddress;

	printf("acpi_probe: %c%c%c%c l=%x oemrev=%x cID=%x crev=%x\n", 
			RSDT->Signature[0], RSDT->Signature[1],
			RSDT->Signature[2], RSDT->Signature[3],
			RSDT->Length, RSDT->OEMRevision, RSDT->CreatorID, RSDT->CreatorRevision);

	return ret;
}
