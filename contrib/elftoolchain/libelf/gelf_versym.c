#include <stdlib.h>
#include <gelf.h>
#include <string.h>

#include "_libelf.h"

GElf_Versym *
gelf_getversym(Elf_Data *data, int ndx, GElf_Versym *dst)
{
	GElf_Versym *result;

	if (data == NULL || data->d_type != ELF_T_HALF) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if (((ndx + 1) * sizeof(GElf_Versym) > data->d_size)) {
		LIBELF_SET_ERROR(RANGE, 0);
		return (NULL);
	}

	*dst = ((GElf_Versym *) data->d_buf)[ndx];

	result = dst;
	return result;
}

GElf_Verdef *
gelf_getverdef(Elf_Data *data, int offset, GElf_Verdef *dst)
{
	GElf_Verdef *result;

	if (data == NULL || data->d_type != ELF_T_VDEF) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if((offset < 0)
		|| (offset + sizeof(GElf_Verdef) > data->d_size)
		|| (offset % __alignof__(GElf_Verdef) != 0)) {
		LIBELF_SET_ERROR(RANGE, 0);
		return (NULL);
	}

	result = (GElf_Verdef *) memcpy(dst, (char *) data->d_buf + offset, sizeof(GElf_Verdef));

	return result;
}

GElf_Verdaux *
gelf_getverdaux (Elf_Data *data, int offset, GElf_Verdaux *dst)
{
	if (data == NULL || data->d_type != ELF_T_VDEF) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if((offset < 0)
		|| (offset + sizeof(GElf_Verdaux) > data->d_size)
		|| (offset % __alignof__ (GElf_Verdaux) != 0)) {
		LIBELF_SET_ERROR(RANGE, 0);
		return (NULL);
	}

	GElf_Verdaux *result;
	result = (GElf_Verdaux *) memcpy(dst, (char *) data->d_buf + offset, sizeof(GElf_Verdaux));

	return result;
}
