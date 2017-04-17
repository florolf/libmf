all: format_picc get_applications get_files get_value change_akey test_auth deploy_club change_value

%.o: %.c
	gcc -std=c99 -I.. -g -c $< `pkg-config --libs --cflags libpcsclite` -o $@

%: %.c pcsc_common.o
	gcc -std=c99 -L.. -g -I.. $^ `pkg-config --libs --cflags libpcsclite` -lmf -o $@
