#ifndef _ACPI_H
#define _ACPI_H

#include "klibc.h"

struct RSDPDescriptor20 {
	char Signature[8];
	uint8 Checksum;
	char OEMID[6];
	uint8 Revision;
	uint32 RsdtAddress;
	uint32 Length;
	uint64 XsdtAddress;
	uint8 ExtendedChecksum;
	uint8 reserved[3];
} __attribute__((packed));

struct ACPISDTHeader {
	char Signature[4];
	uint32 Length;
	uint8 Revision;
	uint8 Checksum;
	char OEMID[6];
	char OEMTableID[8];
	uint32 OEMRevision;
	uint32 CreatorID;
	uint32 CreatorRevision;
} __attribute__((packed));

/*@null@*/ struct RSDPDescriptor20 *acpi_probe();

#endif
