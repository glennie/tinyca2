# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CA.pm,v 1.9 2006/06/28 21:50:41 sm Exp $
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.

use strict;

package CA;

use POSIX;

sub new {
   my $that = shift;
   my $self = {};

   my $class = ref($that) || $that;

   $self->{'init'} = shift;

   if(not -d $self->{'init'}->{'basedir'}) {
      print "create basedir: $self->{'init'}->{'basedir'}\n";
      mkdir($self->{'init'}->{'basedir'}, 0700);
   }

   if(not -d $self->{'init'}->{'tmpdir'}) {
      print "create temp dir: $self->{'init'}->{'tmpdir'}\n";
      mkdir($self->{'init'}->{'tmpdir'}, 0700);
   }

   opendir(DIR, $self->{'init'}->{'basedir'}) || do {
      print _("error: can't open basedir: ").$!;
      exit(1);
   };

   $self->{'calist'} = [];

      while(my $ca = readdir(DIR)) { 
         chomp($ca);
         next if $ca eq ".";
         next if $ca eq "..";
         next if $ca eq "tmp";

         my $dir = $self->{'init'}->{'basedir'}."/".$ca;
         next unless -d $dir;
         next unless -s $dir."/cacert.pem";
         next unless -s $dir."/cacert.key";
         push(@{$self->{'calist'}}, $ca);
         @{$self->{'calist'}} = sort(@{$self->{'calist'}});
         $self->{$ca}->{'dir'} = $dir;
         $self->{$ca}->{'cnf'} = $dir."/openssl.cnf";
      }
      closedir(DIR);

   bless($self, $class);
}

#
# see if the ca can be opened without asking the user
# or show the open dialog
#
sub get_open_name {
   my ($self, $main, $opts) = @_;

   my ($ind);

   if((not defined($opts->{'name'})) || ($opts->{'name'} eq "")) {
      # if only one CA is defined, open it without prompting
      if($#{$self->{'calist'}} == 0) {
         $opts->{'name'} = $self->{'calist'}->[0];
         $self->open_ca($main, $opts);
      } else {
         $main->show_select_ca_dialog('open');
      }
   }
}

#
# open the ca with the given name
#
sub open_ca {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   my ($i, $cnf, @lines, $oldca, $index, $bak, $t);

   GUI::HELPERS::set_status($main, _("  Opening CA: ").$opts->{'name'});
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }

   if(!exists($self->{$opts->{'name'}})) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Invalid CA selected"));
      return;
   }

   # selected CA is already open
   if ((defined($self->{'actca'})) && 
       ($opts->{'name'} eq $self->{'actca'})) { 
      GUI::HELPERS::set_cursor($main, 0);
      print STDERR "DEBUG: ca $opts->{'name'} already opened\n";
      return;
   }

   $self->{'actca'} = $opts->{'name'};
   $self->{'cadir'} = $self->{$opts->{'name'}}->{'dir'};
   $main->{'cadir'} = $self->{'cadir'};

   if(my $dir = HELPERS::get_export_dir($main)) {
      $main->{'exportdir'} = $dir;
   }

   # update config (necessary for update from old tinyca)
   $cnf =  $self->{$opts->{'name'}}->{'cnf'};
   open(IN, "<$cnf");
   @lines = <IN>;
   close(IN);
   for($i = 0; $lines[$i]; $i++) {
      $lines[$i] =~ s/private\/cakey.pem/cacert.key/;
   }
   open(OUT, ">$cnf");
   print OUT @lines;
   close(OUT);

   $main->{'mw'}->set_title( "Tiny CA Management $main->{'version'}".
                             " - $self->{'actca'}"
         );

   $main->{'CERT'}->{'lastread'} = 0;
   $main->{'REQ'}->{'lastread'}  = 0;
   $main->{'KEY'}->{'lastread'}  = 0;

   delete($main->{'OpenSSL'}->{'CACHE'});
   delete($main->{'CERT'}->{'OpenSSL'}->{'CACHE'});
   delete($main->{'REQ'}->{'OpenSSL'}->{'CACHE'});
   delete($main->{'OpenSSL'});

   GUI::HELPERS::set_status($main, _("  Initializing OpenSSL"));
   $main->{'OpenSSL'} = OpenSSL->new(
         $main->{'init'}->{'opensslbin'}, $main->{'tmpdir'});

   $index = $self->{'cadir'}."/index.txt";

   GUI::HELPERS::set_status($main, _("  Check for CA Version"));
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }

   open(INDEX, "+<$index") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(_("Can't open index file: ".$!));
      return;
   };

   while(<INDEX>) {
      if(/Email=/) {
         $oldca = 1;
         last;
      }
   }
   close(INDEX);

   # offer CA conversion for old CAs and openssl >= 0.9.7
   if($oldca && ($main->{'OpenSSL'}->{'version'} eq "0.9.7") &&
         !$opts->{'noconv'} && !$opts->{'doconv'}) {
      GUI::HELPERS::set_status($main, _("  Convert CA"));
      while(Gtk2->events_pending) {
         Gtk2->main_iteration;
      }
      $self->{'actca'} = undef;
      GUI::HELPERS::set_cursor($main, 0);
      $main->show_ca_convert_dialog($opts);
      return;
   }

   if($opts->{'doconv'}) {
      open(INDEX, "+<$index") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_error(_("Can't open index file: ".$!));
         return;
      };
      $bak = $index.".bak";
      open(BAK, "+>$bak") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_error(_("Can't open index backup: ").$!);
         return;
      };
      seek(INDEX, 0, 0);
      while(<INDEX>) {
         print BAK;
      }
      seek(INDEX, 0, 0);
      truncate(INDEX, 0);
      seek(BAK, 0, 0);
      while(<BAK>) {
         $_ =~ s/Email=/emailAddress=/;
         print INDEX;
      }
      close(INDEX);
      close(BAK);

      $t = _("This CA is converted for openssl 0.9.7x now.");
      $t .= "\n";
      $t .= _("You will find a backup copy of the index file at: ");
      $t .= $bak;

      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_info($t);
   }

   GUI::HELPERS::set_cursor($main, 1);

   GUI::HELPERS::set_status($main, _("  Read Configuration"));
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }
   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   GUI::HELPERS::set_status($main, _("  Create GUI"));
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }
   $main->create_mframe(1);

   GUI::HELPERS::set_status($main, _("  Create Toolbar"));
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }
   $main->create_toolbar('ca');

   GUI::HELPERS::set_status($main, _("  Actual CA: ").$self->{'actca'});
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }

   GUI::HELPERS::set_cursor($main, 0);

   $main->{'nb'}->set_current_page(0);

   return;
}

#
# get name for deleting a CA
#
sub get_ca_delete {
   my ($self, $main, $name) = @_;

   if(!defined($name)) {
      $main->show_select_ca_dialog('delete');
      return;
   }elsif(!exists($self->{$name})) {
      $main->show_select_ca_dialog('delete');
      GUI::HELPERS::print_warning(_("Invalid CA selected"));
      return;
   }else {
      $self->delete_ca($main, $name);
   }

   return;
}

#
# delete given CA
#
sub delete_ca {
   my ($self, $main, $name, $box) = @_;

   my ($ind, @tmp, $t);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   _rm_dir($self->{$name}->{'dir'});

   if((defined($self->{'actca'})) && 
      ($name eq $self->{'actca'})) { 
      $self->{'actca'} = undef;
   }
   
   $main->{'cabox'}->destroy() if(defined($main->{'cabox'}));
   delete($main->{'cabox'});

   $main->{'reqbox'}->destroy() if(defined($main->{'reqbox'}));
   delete($main->{'reqbox'});

   $main->{'keybox'}->destroy() if(defined($main->{'keybox'}));
   delete($main->{'keybox'});

   $main->{'certbox'}->destroy() if(defined($main->{'certbox'}));
   delete($main->{'certbox'});

   for(my $i = 0; $i < 4; $i++) {
      $main->{'nb'}->remove_page($i);
   }

   delete($main->{'reqbrowser'});
   delete($main->{'certbrowser'});

   delete($main->{'REQ'}->{'reqlist'});
   delete($main->{'CERT'}->{'certlist'});

   foreach(@{$self->{'calist'}}) {
      next if $_ eq $name;
      push(@tmp, $_);
   }
   $self->{'calist'} = \@tmp;

   delete($self->{$name});

   $main->create_mframe();

   GUI::HELPERS::set_cursor($main, 0);

   $t = sprintf(_("CA: %s deleted"), $name);
   GUI::HELPERS::print_info($t);

   return;
}

#
# check if all data for creating a ca is available
#
sub get_ca_create {
   my ($self, $main, $opts, $box, $mode) = @_;

   $box->destroy() if(defined($box));

   my ($action, $index, $serial, $t, $parsed);

   if(not(defined($opts))) { 
      $opts = {};
      $opts->{'days'} = 3650; # set default to 10 years
      $opts->{'bits'} = 4096;
      $opts->{'digest'} = 'sha1';

      if(defined($mode) && $mode eq "sub") { # create SubCA, use defaults
         $opts->{'parentca'} = $main->{'CA'}->{'actca'};
         
         $parsed = $main->{'CERT'}->parse_cert($main, 'CA');
         if(defined $parsed->{'C'}) {
            $opts->{'C'} = $parsed->{'C'};
         }
         if(defined $parsed->{'ST'}) {
            $opts->{'ST'} = $parsed->{'ST'};
         }
         if(defined $parsed->{'L'}) {
            $opts->{'L'} = $parsed->{'L'};
         }
         if(defined $parsed->{'O'}) {
            $opts->{'O'} = $parsed->{'O'};
         }
         if(defined $parsed->{'OU'}) {
            my $cc = 0;
            foreach my $ou (@{$parsed->{'OU'}}) {
               $opts->{'OU'}->[$cc++] = $ou;
            }
         }
      }
      
      $main->show_ca_dialog($opts, $mode);
      return;
   }

   if(defined($mode) && $mode eq "sub") {
      if(not defined($opts->{'parentpw'})) {
         $main->show_ca_dialog($opts, $mode);
         GUI::HELPERS::print_warning(
             _("Password of parent CA is needed for creating a Sub CA"));
         return;
      }
   }

   if((not defined($opts->{'name'})) || 
	   ($opts->{'name'} eq "") ||
	   ($opts->{'name'} =~ /\s/)) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(_("Name must be filled in and must")
                          ._(" not contain Spaces"));
      return;
   }

   if((not defined($opts->{'C'})) ||
      ($opts->{'C'} eq "") ||
      (not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(
            _("Please specify at least Common Name, ") 
           ._("Country and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
      $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(_("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if(length($opts->{'C'}) != 2) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(_("Country must be exact 2 letter code"));
      return;
   }

   $t = sprintf(_("CA: %s already exists"), $opts->{'name'});
   if(defined($self->{$opts->{'name'}})) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning($t);
      return;
   }

   # warn "call create_ca_env with bits: $opts->{'bits'}\n";

   $self->create_ca_env($main, $opts, $mode);

   return;
}

#
# check if all data for importing a CA is available
#
sub get_ca_import {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($name, $t, $parsed, $constr);

   if(!(defined($opts))) { 
      $opts = {};
      $opts->{'days'} = 3650; # set default to 10 years
      $opts->{'bits'} = 4096;
      $opts->{'digest'} = 'sha1';
      
      $main->show_ca_import_dialog($opts);
      return;
   }

   # check options given in dialog
   if((not defined($opts->{'name'})) || 
	   ($opts->{'name'} eq "") ||
	   ($opts->{'name'} =~ /\s/)) { 
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("Name for storage must be filled in and must not contain spaces"));
      return;
   }

   if(((not defined($opts->{'passwd'})) ||
       ($opts->{'passwd'} eq '')) &&
       (!$opts->{'pwwarning'})) {
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("You didn't give a password for the private CA key.").
            "\n".
            _("The import will fail, if the key is encrypted."));
         $opts->{'pwwarning'} = 1;
      return;
   }

   if((not defined($opts->{'newpasswd'})) ||
      ($opts->{'newpasswd'} eq '')) {
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("Please give a new password for the CA"));
      return;
   }

   if((not defined($opts->{'newpasswd2'})) ||
      $opts->{'newpasswd'} ne $opts->{'newpasswd2'}) { 
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(_("New passwords don't match"));
      return;
   }

   if((not defined($opts->{'cacertfile'})) ||
      ($opts->{'cacertfile'} eq '')) {
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("Please give a CA certificate to import"));
      return;
   }
   if(not -r $opts->{'cacertfile'}) {
      $main->show_ca_import_dialog($opts);
      $t = sprintf(_("Can't read CA certificate file:\n%s"), 
            $opts->{'cacertfile'});
      GUI::HELPERS::print_warning($t);
      return;
   }

   if((not defined($opts->{'cakeyfile'})) ||
      ($opts->{'cakeyfile'} eq '')) {
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("Please give a CA keyfile to import"));
      return;
   }
   if(not -r $opts->{'cakeyfile'}) {
      $main->show_ca_import_dialog($opts);
      $t = sprintf(_("Can't read CA key file:\n%s"), 
            $opts->{'cakeyfile'});
      GUI::HELPERS::print_warning($t);
      return;
   }

   if(((not defined($opts->{'indexfile'})) ||
       ($opts->{'indexfile'} eq '')) &&
      (not defined($opts->{'indexwarning'}))) {

      $main->show_ca_import_dialog($opts);

      $t = _("Please give an Index file to import.\n");
      $t .= _("If you don't have an Index file, i'll try to generate one.\n");
      $t .= _("Attention: This will cause all Certificates to show up as valid.\n");
      $t .= _("Attention: Revoked Certificates will not be determined.");

      $opts->{'indexwarning'} = 1;

      GUI::HELPERS::print_warning($t);
      return;
   }
   if(defined($opts->{'indexfile'}) && 
      $opts->{'indexfile'} ne '' &&
      not -r $opts->{'indexfile'}) {
      $main->show_ca_import_dialog($opts);
      $t = sprintf(_("Can't read Index file:\n%s"), 
            $opts->{'indexfile'});
      GUI::HELPERS::print_warning($t);
      return;
   } elsif(defined($opts->{'indexfile'}) &&
           $opts->{'indexfile'} ne '') {
      $opts->{'gotindex'} = 1;
   }

   if((not defined($opts->{'certdir'})) ||
      ($opts->{'certdir'} eq '')) {
      $main->show_ca_import_dialog($opts);
      GUI::HELPERS::print_warning(
            _("Please give a directory containing the certificates to import"));
      return;
   }
   if(not -d $opts->{'certdir'}) {
      $main->show_ca_import_dialog($opts);
      $t = sprintf(_("Can't find certificate directory:\n%s"), 
            $opts->{'certdir'});
      GUI::HELPERS::print_warning($t);
      return;
   }

   $name = $opts->{'name'};

   if(defined($self->{$name})) { 
      $main->show_ca_import_dialog($opts);
      $t = sprintf(
            _("CA: %s already exists. Please choose another name"), 
            $name);
      GUI::HELPERS::print_warning($t);
      return;
   }

   # check ca certificate and key
   $parsed = $main->{'OpenSSL'}->parsecert(
         undef, undef, $opts->{'cacertfile'}, 1);

   # check if it's really a CA certificate
   if(defined($parsed->{'EXT'}->{'X509v3 Basic Constraints: critical'})) {
      $constr = $parsed->{'EXT'}->{'X509v3 Basic Constraints: critical'}->[0];
   } elsif(defined($parsed->{'EXT'}->{'X509v3 Basic Constraints'})) {
      $constr = $parsed->{'EXT'}->{'X509v3 Basic Constraints'}->[0];
   } else {
      $t = _("Can't find X509v3 Basic Constraints in CA Certificate\n");
      $t .= _("Import canceled");
      GUI::HELPERS::print_warning($t);
      return;
   }
   
   if($constr !~ /CA:TRUE/i) {
      $t = _("The selected CA Certificate is no valid CA certificate\n");
      $t .= sprintf(_("X509v3 Basic Constraint is set to: %s"), $constr);
      GUI::HELPERS::print_warning($t);
      return;
   }

   $opts->{'cacertdata'} = $parsed->{'PEM'};

   # now read the data from the files
   if(defined($opts->{'gotindex'})) {
      open(INDEX, "<$opts->{'indexfile'}") || do {
         $t = sprintf(_("Can't open Index file:\n%s"), 
               $opts->{'indexfile'});
         GUI::HELPERS::print_warning($t);
         return;
      };
      while(<INDEX>) {
         $opts->{'serial'} = hex((split(/\t/, $_))[3]);
         $opts->{'indexdata'} .= $_;
      }
      close(INDEX);
      $opts->{'serial'} +=1;
      $opts->{'serial'} = sprintf("%x", $opts->{'serial'});
   }

   $main->show_import_verification("cacert", $opts, $parsed);

   return;
}

#
# do the real import
#
sub import_ca {
   my ($self, $main, $opts, $box) = @_;

   my ($t, $f, $cacertfile, $cakeyfile, $certfile, $c, $p, @files, $ext, $ret,
         @d, $timestring, $indexline, $index, $serial, $subjects, $serials,
         $timestrings);

   my $format = "DER";
   my $data   = {};
   my $ca     = $opts->{'name'};

   if (hex($opts->{'serial'}) < 1) {
      $opts->{'serial'} = "01";
   }

   if(defined($box)) {
      $box->destroy();
   }

   $opts->{'cakeydata'} = $main->{'KEY'}->key_change_passwd(
         $main, $opts->{'cakeyfile'}, $opts->{'passwd'},
         $opts->{'newpasswd'});

   if($opts->{'cakeydata'} eq 1) {
      return;
   }

   $self->create_ca_env($main, $opts, 'import');

   # now read all certificates
   opendir(DIR, $opts->{'certdir'}) || do {
      $t = sprintf(_("Can't open Certificate directory: %s"),
            $opts->{'certdir'}); 
      GUI::HELPERS::print_warning($t); 
      return; 
   };

   # just count the files
   while($f = readdir(DIR)) {
      next if($f =~ /^\./);
      $certfile = $opts->{'certdir'}."/".$f;
      push (@files, $certfile);
      $c++;
   }

   GUI::HELPERS::set_cursor($main, 1);

   # import all the certificate files and gather information if necessary
   $main->{'barbox'}->pack_start($main->{'progress'}, 0, 0, 0);
   foreach $certfile (@files) {
      $t = sprintf(_("   Read Certificate: %s"), $certfile);
      GUI::HELPERS::set_status($main, $t);
      $p += 100/$c;
      $main->{'progress'}->set_fraction($p/100);
      while(Gtk2->events_pending) {
         Gtk2->main_iteration;
      }

      open(IN, "<$certfile") || do {
         GUI::HELPERS::set_cursor($main, 0);
         $t = sprintf(_("Can't read Certificate file: %s"), $certfile);
         return;
      };
      $data->{'raw'} = '';
      $data->{'raw'} .= $_ while(<IN>);
      close(IN);
      $format = "PEM" if($data->{'raw'} =~ /BEGIN CERTIFICATE/);

      if($format eq "PEM") {
         $data->{'PEM'} = $data->{'raw'};
      }
      
      $data->{'parsed'} = $main->{'OpenSSL'}->parsecert(
            undef, undef, $certfile, 1
            );

      $data->{'name'} = HELPERS::gen_name($data->{'parsed'});
      $data->{'name'} = HELPERS::enc_base64($data->{'name'});
      $data->{'name'} .= ".pem";

      $data->{'file'} = $self->{$ca}->{'dir'}."/certs/".$data->{'name'};

      open(OUT, ">$data->{'file'}") || do {
         GUI::HELPERS::set_cursor($main, 0);
         $t = sprintf(_("Can't write Certificate file: %s"),
               $data->{'file'}); 
         return; 
      };
      print OUT $data->{'PEM'};

      if(not defined($opts->{'gotindex'})) {
         # get information for index.txt file
         @d = localtime($data->{'parsed'}->{'EXPDATE'});
         $timestring = sprintf("%02d%02d%02d%02d%02d%02dZ",
               $d[5]%100, $d[4]+1, $d[3], $d[2], $d[1], $d[0]);

         # try to detect index clashes FIXME: only the newer is kept
         if(exists($subjects->{$data->{'parsed'}->{'SUBJECT'}})) {
            if(hex($data->{'parsed'}->{'SERIAL'}) >=
                  hex($serials->{$data->{'parsed'}->{'SUBJECT'}})) {
               $subjects->{$data->{'parsed'}->{'SUBJECT'}} = 1;
               $serials->{$data->{'parsed'}->{'SUBJECT'}} =
                  $data->{'parsed'}->{'SERIAL'};
               $timestrings->{$data->{'parsed'}->{'SUBJECT'}} =
                  $timestring;
            }
         } else { 
            $subjects->{$data->{'parsed'}->{'SUBJECT'}} = 1;
            $serials->{$data->{'parsed'}->{'SUBJECT'}} = 
               $data->{'parsed'}->{'SERIAL'}; 
            $timestrings->{$data->{'parsed'}->{'SUBJECT'}} = 
               $timestring;
         }

         # get information for serial file
         if(hex($data->{'parsed'}->{'SERIAL'}) >= hex($opts->{'serial'})) {
            $opts->{'serial'} = sprintf("%x", hex($data->{'parsed'}->{'SERIAL'}));
         }
         $opts->{'serial'} = hex($opts->{'serial'}) + 1;
         $opts->{'serial'} = sprintf("%x", $opts->{'serial'});
      }

      close(OUT);
   }

   # now build the indexdata
   foreach my $s (keys(%$subjects)) {
      $indexline = "V\t$timestrings->{$s}\t\t$serials->{$s}\tunknown\t$s\n";
      $opts->{'indexdata'} .= $indexline;
   }
   
   # create index file
   $index = $self->{$ca}->{'dir'}."/index.txt";
   open(OUT, ">$index") || do {
      GUI::HELPERS::print_error(_("Can't open Index file: ").$!);
      return;
   };
   print OUT $opts->{'indexdata'};
   close OUT;

   $cacertfile = $self->{$ca}->{'dir'}."/cacert.pem";
   $cakeyfile  = $self->{$ca}->{'dir'}."/cacert.key";

   # write cacertfile
   open(OUT, ">$cacertfile") || do {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(_("Can't write CA Certificate file: %s"),
            $cacertfile); 
      return; 
   };
   print OUT $opts->{'cacertdata'};
   close(OUT);

   # check serial number of CA file
   $data->{'parsed'} = $main->{'OpenSSL'}->parsecert( 
         undef, undef, $cacertfile, 1
         );
   if(hex($data->{'parsed'}->{'SERIAL'}) >= hex($opts->{'serial'})) {
      $opts->{'serial'} = sprintf("%x", hex($opts->{'serial'}));
   }
   $opts->{'serial'} = hex($opts->{'serial'}) + 1;
   $opts->{'serial'} = sprintf("%x", $opts->{'serial'});

   # create serial file
   $serial = $self->{$ca}->{'dir'}."/serial";
   open(OUT, ">$serial") || do {
      GUI::HELPERS::print_error(_("Can't write Serial file: ").$!);
      return;
   };

   if($opts->{'serial'} ne "") {
      print OUT uc($opts->{'serial'});
   }else{
      print OUT "01";
   }
   close OUT;

   # write keyfile
   open(OUT, ">$cakeyfile") || do {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(_("Can't write CA Key file: %s"),
            $cakeyfile); 
      return; 
   };
   print OUT $opts->{'cakeydata'};
   close(OUT);

   ($ret, $ext) = $main->{'OpenSSL'}->newcrl(
         config  => $self->{$ca}->{'cnf'},
         pass    => $opts->{'newpasswd'},
         crldays => 30,
         outfile => $self->{$ca}->{'dir'}."/crl/crl.pem",
         format  => 'PEM'
         );

   if ((not -s $self->{$ca}->{'dir'}."/crl/crl.pem") || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(_("Generating CRL failed"), $ext);
      print STDERR "DEBUG: newcrl returned $ext\n";
      die;
      return;
   }


   GUI::HELPERS::set_cursor($main, 0);
   $main->{'barbox'}->remove($main->{'progress'});

   push(@{$self->{'calist'}}, $ca);
   @{$self->{'calist'}} = sort(@{$self->{'calist'}});

   $t = sprintf(_("Succesfully imported %d certificates\n"), $c);
   $t.= _("Check the configuration of your imported CA.");
   GUI::HELPERS::print_info($t);

   $self->open_ca($main, $opts);

   return;
}

#
# create a new CA, environment: dirs, etc.
#
sub create_ca_env {
   my ($self, $main, $opts, $mode) = @_;

   my ($t, $index, $serial);

   if((!defined($opts->{'name'})) || $opts->{'name'} eq '') {
      GUI::HELPERS::print_error(_("No CA name given"));
      return;
   }
 
   # create directories
   $self->{$opts->{'name'}}->{'dir'} = 
      $self->{'init'}->{'basedir'}."/".$opts->{'name'};

   mkdir($self->{$opts->{'name'}}->{'dir'}, 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$opts->{'name'}}->{'dir'}."/req", 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$opts->{'name'}}->{'dir'}."/keys", 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$opts->{'name'}}->{'dir'}."/certs", 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$opts->{'name'}}->{'dir'}."/crl", 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$opts->{'name'}}->{'dir'}."/newcerts", 0700) || do { 
      GUI::HELPERS::print_warning(_("Can't create directory: ").$!);
      return;
   };

   # create configuration file
   my $in  = $self->{'init'}->{'templatedir'}."/openssl.cnf";
   my $out = $self->{$opts->{'name'}}->{'dir'}."/openssl.cnf";

   open(IN, "<$in") || do {
      $t = sprintf(_("Can't open template file %s %s"), $in, $!);
      GUI::HELPERS::print_error($t);
      return;
   };
   open(OUT, ">$out") || do {
      $t = sprintf(_("Can't open output file: %s: %s"),$out, $!);
      GUI::HELPERS::print_error($t);
      return;
   };
   while(<IN>) {
      s/\%dir\%/$self->{$opts->{'name'}}->{'dir'}/;
      print OUT;
   }
   close IN;
   close OUT;
   $self->{$opts->{'name'}}->{'cnf'} = $out;

   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   # create some more files
   $index = $self->{$opts->{'name'}}->{'dir'}."/index.txt";
   open(OUT, ">$index") || do {
      GUI::HELPERS::print_error(_("Can't open Index file: ").$!);
      return;
   };
   close(OUT);

   $serial = $self->{$opts->{'name'}}->{'dir'}."/serial";
   open(OUT, ">$serial") || do {
      GUI::HELPERS::print_error(_("Can't write Serial file: ").$!);
      return;
   };

   if(defined($opts->{'serial'}) && $opts->{'serial'} ne "") {
      print OUT uc($opts->{'serial'});
   }else{
      print OUT "01";
   }
   close(OUT);

   if(defined($mode) && $mode eq "sub") {
      $self->create_ca($main, $opts, undef, $mode);
   } elsif(defined($mode) && $mode eq "import") {
   } else {
      GUI::TCONFIG::show_config_ca($main, $opts, $mode);
   }

   return;
}

#
# now create the CA certificate and CRL
#
sub create_ca {
   my ($self, $main, $opts, $box, $mode) = @_;

   my ($fname, $t, $index, $serial, $ca, $ret, $ext);

   $ca = $self->{'actca'};

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   if((!defined($opts->{'name'})) || $opts->{'name'} eq '') {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(_("No CA name given"));
      return;
   }

   # create CA certifikate
   ($ret, $ext) = $main->{'OpenSSL'}->newkey( 
         'bits'    => $opts->{'bits'},
         'outfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.key",
         'pass'    => $opts->{'passwd'}
         );
   
   if (not -s $self->{$opts->{'name'}}->{'dir'}."/cacert.key" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Generating key failed"), $ext);
      _rm_dir($self->{$opts->{'name'}}->{'dir'});
      delete($self->{$opts->{'name'}});
      return;
   }

   my @dn = ( 
         $opts->{'C'}, 
         $opts->{'ST'}, 
         $opts->{'L'}, 
         $opts->{'O'}, 
         $opts->{'OU'}->[0],
         $opts->{'CN'}, 
         $opts->{'EMAIL'}, 
         '', 
         '');

   ($ret, $ext) = $main->{'OpenSSL'}->newreq( 
         'config'  => $self->{$opts->{'name'}}->{'cnf'},
         'outfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.req",
         'digest'   => $opts->{'digest'},
         'pass'    => $opts->{'passwd'},
         'dn'      => \@dn,
         'keyfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.key"
         );

   $fname = HELPERS::gen_name($opts);

   $opts->{'reqname'} = HELPERS::enc_base64($fname);
   
   if (not -s $self->{$opts->{'name'}}->{'dir'}."/cacert.req" || $ret) {
      unlink($self->{$opts->{'name'}}->{'dir'}."/cacert.key");
      unlink($self->{$opts->{'name'}}->{'dir'}."/cacert.req");
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Generating Request failed"), $ext);
      _rm_dir($self->{$opts->{'name'}}->{'dir'});
      delete($self->{$opts->{'name'}});
      return;
   } else {
   if(defined($mode) && $mode eq "sub") {
      # for SubCAs: copy the request to the signing CA
      open(IN, "<$self->{$opts->{'name'}}->{'dir'}"."/cacert.req") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/req/".$opts->{'reqname'}.".pem") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;

      # for SubCAs: copy the key to the signing CA
      open(IN, "<$self->{$opts->{'name'}}->{'dir'}"."/cacert.key") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/keys/".$opts->{'reqname'}.".pem") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;
    }
   }

   if(defined($mode) && $mode eq "sub") {
      ($ret, $ext) = $main->{'REQ'}->sign_req(
            $main,
            {
            'mode'       => "sub",
            'config'     => $self->{$opts->{'name'}}->{'cnf'},
            'outfile'    => $self->{$opts->{'name'}}->{'dir'}."/cacert.pem",
            'reqfile'    => $self->{$opts->{'name'}}->{'dir'}."/cacert.req",
            'outdir'     => $self->{$ca}->{'dir'}."/newcerts/",
            'keyfile'    => $self->{$ca}->{'dir'}."/cacert.key",
            'cacertfile' => $self->{$ca}->{'dir'}."/cacert.pem",
            'pass'       => $opts->{'passwd'},
            'days'       => $opts->{'days'},
            'parentpw'   => $opts->{'parentpw'},
            'reqname'    => $opts->{'reqname'}
            }
            );
   } else {
      ($ret, $ext) = $main->{'OpenSSL'}->newcert( 
            'config'  => $self->{$opts->{'name'}}->{'cnf'},
            'outfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.pem",
            'keyfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.key",
            'reqfile' => $self->{$opts->{'name'}}->{'dir'}."/cacert.req",
            'digest'  => $opts->{'digest'},
            'pass'    => $opts->{'passwd'},
            'days'    => $opts->{'days'}
            );
   }
   
   if (not -s $self->{$opts->{'name'}}->{'dir'}."/cacert.pem" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            _("Generating certificate failed"), $ext);
      _rm_dir($self->{$opts->{'name'}}->{'dir'});
      delete($self->{$opts->{'name'}});
      return;
   }

   unlink($self->{$opts->{'name'}}->{'dir'}."/cacert.req");

   if(defined($mode) && $mode eq "sub") {
     # create file containing chain of ca certificates
     my $in;
     if (-f $self->{$ca}->{'dir'}."/cachain.pem") {
       $in   = $self->{$ca}->{'dir'}."/cachain.pem";
     } else {
       $in   = $self->{$ca}->{'dir'}."/cacert.pem";
     }
     my $out  = $self->{$opts->{'name'}}->{'dir'}."/cachain.pem";

     open(IN, "<$in") || do {
        $t = sprintf(
              _("Can't open ca certificate file %s %s"), $in, $!);
        GUI::HELPERS::set_cursor($main, 0);
        GUI::HELPERS::print_warning($t);
        _rm_dir($self->{$opts->{'name'}}->{'dir'});
        delete($self->{$opts->{'name'}});
        return;
     };
     open(OUT, ">$out") || do {
        $t = sprintf(
              _("Can't create certificate chain file: %s: %s"),$out, $!);
        GUI::HELPERS::set_cursor($main, 0);
        $main->print_warning($t);
        _rm_dir($self->{$opts->{'name'}}->{'dir'});
        delete($self->{$opts->{'name'}});
        return;
     };
     while(<IN>) {
        print OUT;
     }
     close IN;

     # now append the certificate of the created SubCA
     $in  = $self->{$opts->{'name'}}->{'dir'}."/cacert.pem";
     open(IN, "<$in") || do {
        $t = sprintf(
              _("Can't open ca certificate file %s %s"), $in, $!);
        GUI::HELPERS::set_cursor($main, 0);
        GUI::HELPERS::print_warning($t);
        _rm_dir($self->{$opts->{'name'}}->{'dir'});
        delete($self->{$opts->{'name'}});
        return;
     };

     while(<IN>) {
        print OUT;
     }
     close OUT;
   }

   ($ret, $ext) = $main->{'OpenSSL'}->newcrl(
         config  => $self->{$opts->{'name'}}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'},
         outfile => $self->{$opts->{'name'}}->{'dir'}."/crl/crl.pem",
         format  => 'PEM'
         );

   if (not -s $self->{$opts->{'name'}}->{'dir'}."/crl/crl.pem" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Generating CRL failed"), $ext);
      _rm_dir($self->{$opts->{'name'}}->{'dir'});
      delete($self->{$opts->{'name'}});
      return;
   }

   # seems to be done
   push(@{$self->{'calist'}}, $opts->{'name'});
   @{$self->{'calist'}} = sort(@{$self->{'calist'}});
   $t = sprintf(_("CA: %s created"), $opts->{'name'});
   GUI::HELPERS::set_cursor($main, 0);

   GUI::HELPERS::print_info($t);

   $self->open_ca($main, $opts);
   return;
}

#
# export ca certificate chain
#
sub export_ca_chain {
   my ($self, $main, $opts, $box) = @_;

   my($ca, $chainfile, $parsed, $out, $t);

   $box->destroy() if(defined($box));

   $ca = $self->{'actca'};

   if(not defined($opts)) {
      $opts->{'format'}  = 'PEM';
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-cachain.pem";
      $main->show_ca_chain_export_dialog($opts);
      return;
   }

   GUI::HELPERS::set_cursor($main, 1);

   $chainfile = $self->{$ca}->{'dir'}."/cachain.pem";

   open(IN, "<$self->{$ca}->{'dir'}"."/cachain.pem") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            _("Can't open certificate chain file: %s: %s"),
            $self->{$ca}->{'dir'}."/cachain.pem", $!);
      return;
   };

   open(OUT, ">$opts->{'outfile'}") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            _("Can't open output file: %s: %s"), 
            $opts->{'outfile'}, $!);
      return;
   };

   print OUT while(<IN>);
   close OUT;

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});
   
   GUI::HELPERS::set_cursor($main, 0);

   $t = sprintf(_("Certificate Chain succesfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t);

   return;
}

#
# export ca certificate
#
sub export_ca_cert {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $certfile, $parsed, $out, $t);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $self->{'actca'};

   $certfile = $self->{$ca}->{'dir'}."/cacert.pem";

   if(not defined($opts)) {
      $opts->{'format'}  = 'PEM';
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-cacert.pem";
      GUI::HELPERS::set_cursor($main, 0);
      $main->show_ca_export_dialog($opts);
      return;
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   if(not defined $parsed) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(_("Can't read CA certificate"));
   }

   if($opts->{'format'} eq "PEM") {
      $out = $parsed->{'PEM'};
   } elsif ($opts->{'format'} eq "DER") {
      $out = $parsed->{'DER'};
   } elsif ($opts->{'format'} eq "TXT") {
      $out = $parsed->{'TEXT'};
   } else {
      $t = sprintf(_("Invalid Format for export_ca_cert(): %s"), 
            $opts->{'format'});
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning($t);
      return;
   }

   open(OUT, ">$opts->{'outfile'}") || do {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(_("Can't open output file: %s: %s"), 
            $opts->{'outfile'}, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   print OUT $out;
   close OUT;

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});
   
   GUI::HELPERS::set_cursor($main, 0);
   $t = sprintf(_("Certificate succesfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t);

   return;
}

#
# export crl
#
sub export_crl {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $t, $ret, $ext);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $self->{'actca'};

   if(not defined($opts)) {
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-crl.pem";
      $opts->{'format'}  = 'PEM';
      $opts->{'days'} = $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'};

      GUI::HELPERS::set_cursor($main, 0);
      $main->show_crl_export_dialog($opts);
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) { 
      GUI::HELPERS::set_cursor($main, 0);
      $t = _("Please give the output file");
      $main->show_crl_export_dialog($opts);
      GUI::HELPERS::print_warning($t);
	   return;
      };

   if((not defined($opts->{'passwd'})) || ($opts->{'passwd'} eq '')) { 
      GUI::HELPERS::set_cursor($main, 0);
      $t = _("Please give the CA password to create the Revocation List");
      $main->show_crl_export_dialog($opts);
      GUI::HELPERS::print_warning($t);
      return;
   }

   if(not defined($main->{'OpenSSL'})) {
      $main->init_openssl($ca);
   }

   ($ret, $ext) = $main->{'OpenSSL'}->newcrl(
         config  => $self->{$ca}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $opts->{'days'},
         outfile => $opts->{'outfile'},
         format  => $opts->{'format'}
         );

   GUI::HELPERS::set_cursor($main, 0);

   if($ret eq 1) {
      $t = _("Wrong CA password given\nGenerating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   } elsif($ret eq 2) {
      $t = _("CA Key not found\nGenerating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   } elsif($ret) {
      $t = _("Generating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   if (not -s $opts->{'outfile'}) {
      $t = _("Generating Revocation List failed");
      GUI::HELPERS::print_warning($t);
      return;
   }

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});

   $t = sprintf(_("CRL successfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t, $ext);

   return;
}

sub _rm_dir {
   my $dir = shift;

   my $dirh;

   opendir($dirh, $dir);

   while(my $f = readdir($dirh)) {
      next if $f eq '.';
      next if $f eq '..';

      if(-d $dir."/".$f) {
         _rm_dir($dir."/".$f);
      } else {
         unlink($dir."/".$f);
      }
   }
   closedir(DIR);

   rmdir($dir);
   
   return(0);
}

1
