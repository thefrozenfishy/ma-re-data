#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define warn(fmt, ...) fprintf(stderr, "%s:%d: "fmt": %s\n", __FILE__, __LINE__, __VA_ARGS__, strerror(errno))
#define warnx(fmt, ...) fprintf(stderr, "%s:%d: "fmt"\n", __FILE__, __LINE__, __VA_ARGS__)
#define err(e, ...) do { warn(__VA_ARGS__); return e; } while (0)
#define errx(e, ...) do { warnx(__VA_ARGS__); return e; } while (0)

static const unsigned char mask_set[96] = {
	134,74,72,15,250,19,97,121,146,209,183,181,134,131,124,2,
	144,233,253,31,200,0,146,29,121,2,213,36,97,9,129,22,
	121,181,183,240,5,236,158,134,109,46,72,74,121,124,131,253,
	111,22,2,224,55,255,109,226,134,253,42,219,158,246,126,233,
	121,85,183,82,5,85,158,67,109,85,72,82,121,85,131,67,
	111,85,2,82,55,85,109,67,134,85,42,82,158,85,126,67,
};

int main(int argc, char **argv) {
	unsigned char *buf = realloc(0, 65536);
	for (char **a = argv+1; *a; a++) {
		char *filename = *a;
		printf("%s\n", filename);
		size_t name_len = strlen(filename);
		if (name_len > 65531)
			errx(2, "filename too long: %s", filename);

		FILE *in = fopen(filename, "rb");
		if (!in)
			err(2, "open: %s", filename);

		strcpy((char *)buf, filename);
		strcpy((char *)buf+name_len, ".adx");
		FILE *aout = fopen((char *)buf, "wb");
		if (!aout)
			err(2, "open: %s", buf);
		strcpy((char *)buf+name_len, ".m2v");
		FILE *vout = fopen((char *)buf, "wb");
		if (!vout)
			err(2, "open: %s", buf);

		for (;;) {
			if (fread(buf, 4, 1, in) == 0)
				break;
			uint32_t magic = buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24);
			switch (magic) {
			case 0x44495243: // CRID
			case 0x56465340: // @SFV
			case 0x41465340: // @SFA
			case 0x45554340: // @CUE
				break;
			default:
				errx(2, "unknown magic number: %x", magic);
			}

			if (fread(buf, 1, 4, in) != 4)
				err(1, "short read %s", "len");
			uint32_t len = (buf[0]<<24)+(buf[1]<<16)+(buf[2]<<8)+buf[3];

			if (len >= 65536) {
				buf = realloc(buf, len);
				if (!buf)
					err(1, "malloc %u", len);
			}
			if (fread(buf, 1, len, in) != len)
				err(1, "short read %s", "data");

			uint16_t off = (buf[0] << 8) + buf[1];
			uint32_t s = len - off - (buf[2] << 8) - buf[3];
			unsigned char *p = buf+off;

			if (buf[7]) {
				/* metadata we don't care about */
				continue;
			}
			else if (magic == 0x41465340) {
				// @SFA
				for (uint32_t j = 320; j < s; j++)
					p[j] ^= mask_set[64+(j&31)];
				fwrite(p, 1, s, aout);
			}
			else if (magic == 0x56465340) {
				// @SFV
				if (s >= 576) {
					unsigned char mask[32];
					memcpy(mask, mask_set+32, 32);

					for (uint32_t j = 320; j < s; j++)
						mask[j&31] = (p[j] ^= mask[j&31]) ^ mask_set[32+(j&31)];

					memcpy(mask, mask_set, 32);
					for (uint32_t j = 64; j < 320; j++)
						p[j] ^= mask[j&31] ^= p[j+256];
				}
				fwrite(p, 1, s, vout);
			}
			else
				warnx("unrecognised non-metadata with magic %x", magic);
		}

		fclose(in);
		fclose(aout);
		fclose(vout);
	}

	return 0;
}
