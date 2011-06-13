#! /usr/bin/awk -f
# pkcstv2c.awk - Convert pkcs1 test vectors into a C table.
# Copyright 2011 Free Software Foundation, Inc.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

BEGIN {
    in_key = 0;
    in_item = 0;
    in_number = 0;
    no_comma = 0;

    printf "  static struct {\n";
    printf "    const char *desc;\n";
    printf "    const char *n, *e, *d;\n";
    printf "    struct {\n";
    printf "      const char *desc;\n";
    printf "      const char *mesg;\n";
    printf "      const char *seed;\n";
    printf "      const char *encr;\n";
    printf "    } m[20];\n";
    printf "  } tbl[] =\n";
    printf "  {\n";
}

{ sub (/\r/,""); }

/^# Public key/  { skip_pub = 1; }
/^# Private key/ { skip_pub = 0; }
skip_pub { next }

in_number && ! /^[0-9a-f]/ {
    if (in_number == 2)
        printf "\"";
    if (no_comma)
        no_comma = 0;
    else
        printf ","
    printf "\n";
    in_number = 0;
}

in_number == 3 {
    printf "\n";
    in_number = 1;
}

in_number == 1 {
    gsub (/ /,"")
    printf "%*s\"%s", indent, "", $0;
    in_number = 2;
    next;
}

in_number == 2 {
    gsub (/ /,"")
    printf "%s\"", $0;
    in_number = 3;
    next;
}

/^#.*Example.*key pair/ {
    if (in_item) {
        printf "        }\n      }\n    },\n";
        in_item = 0;
    }
    in_key = 1;
    indent = 6;
    printf "    {\n      \"%s\",\n", gensub(/.*: (A .*)/, "\\1", "g");
    next
}

/^# PKCS#1 .*Example/  {
    if (in_key) {
        printf "      {\n";
        in_key = 0;
    }
    if (in_item)
        printf "        },{\n";
    else
        printf "        {\n";
    in_item = 1;
    indent = 10;
    printf "          \"%s\",\n",  gensub(/^# (.*)/, "\\1", "g");
    next
}

(in_key || in_item) && /^# (Modulus|Public|Exponent|Message|Seed)/ {
    # printf "/* %s */\n", $0;
    in_number = 1;
    next
}
(in_key || in_item) && /^# (Signature|Encryption)/ {
    # printf "/* %s */\n", $0;
    in_number = 1;
    no_comma = 1;
    next
}

END {
    if (in_item) {
        printf "        }\n      }\n    }\n  };\n";
        in_item = 0;
    }
}