#include <gelf.h>

#include "_libelf.h"

#define NOTE_ALIGN(n)	(((n) + 3) & -4U)

size_t gelf_getnote(Elf_Data *data, size_t offset, GElf_Nhdr *result,
					size_t *name_offset, size_t *desc_offset) {
	if(data == NULL || data->d_type != ELF_T_NOTE) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return 0;
	}

	if(offset + sizeof(GElf_Nhdr) > data->d_size) {
		LIBELF_SET_ERROR(RANGE, 0);
		return 0;
	}

	const GElf_Nhdr *n = data->d_buf + offset;
	offset += sizeof(*n);

	GElf_Word namesz = NOTE_ALIGN(n->n_namesz);
	GElf_Word descsz = NOTE_ALIGN(n->n_descsz);

	if(data->d_size - offset < descsz) {
		offset = 0;
	} else {
		*name_offset = offset;
		offset += namesz;
		if (data->d_size - offset < descsz) {
			offset = 0;
		} else {
			*desc_offset = offset;
			offset += descsz;
			*result = *n;
		}
	}

	return offset;
}
