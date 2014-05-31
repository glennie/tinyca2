# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: OpenSSL.pm,v 1.14 2006/07/13 22:36:13 sm Exp $
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

package OpenSSL;

use POSIX;
use IPC::Open3;
use Time::Local;

sub new {
   my $self  = {};
   my ($that, $opensslbin, $tmpdir) = @_;
   my $class = ref($that) || $that;

   $self->{'bin'} = $opensslbin;
   my $t = sprintf("Can't execute OpenSSL: %s", $self->{'bin'});
   GUI::HELPERS::print_error($t)
      if (! -x $self->{'bin'});

   $self->{'tmp'}  = $tmpdir;

   open(TEST, "$self->{'bin'} version|");
   my $v = <TEST>;
   close(TEST);

   # set version (format: e.g. 0.9.7 or 0.9.7a)
   if($v =~ /\b(0\.9\.[678][a-z]?)\b/) {
      $self->{'version'} = $1;
   }

   # CRL output was broken before openssl 0.9.7f   
   if($v =~ /\b0\.9\.[0-6][a-z]?\b/ || $v =~ /\b0\.9\.7[a-e]?\b/)  { 
      $self->{'broken'} = 1; 
   } else { 
      $self->{'broken'} = 0; 
   }

   bless($self, $class);
}

sub newkey {
   my $self = shift;
   my $opts = { @_ };

   my ($cmd, $ext, $c, $i, $box, $bar, $t, $param, $pid, $ret);

   if(defined($opts->{'algo'}) && $opts->{'algo'} eq "dsa") {
      $param = HELPERS::mktmp($self->{'tmp'}."/param");
      
      $cmd = "$self->{'bin'} dsaparam";
      $cmd .= " -out $param";
      $cmd .= " $opts->{'bits'}";
      my($rdfh, $wtfh);
      $ext = "$cmd\n\n";
      $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
      $t = _("Creating DSA key in progress...");
      ($box, $bar) = GUI::HELPERS::create_activity_bar($t);
      $i = 0;
      while(defined($c = getc($rdfh))) {
         $ext .= $c;
         $bar->pulse();
         while(Gtk2->events_pending) {
            Gtk2->main_iteration;
         }
      }
      $box->destroy();
      waitpid($pid, 0);
      $ret = $? >> 8;
      return($ret, $ext) if($ret);

      $cmd = "$self->{'bin'} gendsa";
      $cmd .= " -des3";
      $cmd .= " -passout env:SSLPASS";
      $cmd .= " -out \"$opts->{'outfile'}\"";
      $cmd .= " $param";
   } else {
      $cmd = "$self->{'bin'} genrsa";
      $cmd .= " -des3";
      $cmd .= " -passout env:SSLPASS";

      $cmd .= " -out \"$opts->{'outfile'}\"";

      $cmd .= " $opts->{'bits'}";
   }

   $ENV{'SSLPASS'} = $opts->{'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   $t = _("Creating RSA key in progress...");
   ($box, $bar) = GUI::HELPERS::create_activity_bar($t);
   $i = 0;
   while(defined($c = getc($rdfh))) {
      $ext .= $c;
#$bar->update(($i++%100)/100);
      $bar->pulse();
      while(Gtk2->events_pending) {
         Gtk2->main_iteration;
      }
   }
   $box->destroy();

   waitpid($pid, 0);
   $ret = $? >> 8;

   if(defined($param) && $param ne '') {
      unlink($param);
   }
   
   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub signreq {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $pid, $ret);

   $cmd = "$self->{'bin'} ca -batch";
   $cmd .= " -passin env:SSLPASS -notext";
   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -name $opts->{'caname'}" if($opts->{'caname'} ne "");
   $cmd .= " -in \"$opts->{'reqfile'}\"";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -preserveDN";
   $cmd .= " -md $opts->{'digest'}" if($opts->{'digest'});

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $cmd .= " -keyfile \"$opts->{'keyfile'}\"";
      $cmd .= " -cert \"$opts->{'cacertfile'}\"";
      $cmd .= " -outdir \"$opts->{'outdir'}\"";
      $ENV{'SSLPASS'} = $opts->{'parentpw'};
   } else {
      $ENV{'SSLPASS'} = $opts->{'pass'};
   }

   if(defined($opts->{'sslservername'}) && $opts->{'sslservername'} ne 'none') {
      $ENV{'NSSSLSERVERNAME'} = $opts->{'sslservername'};
   }
   if(defined($opts->{'revocationurl'}) && $opts->{'revocationurl'} ne 'none') {
      $ENV{'NSREVOCATIONURL'} = $opts->{'revocationurl'};
   }
   if(defined($opts->{'renewalurl'}) && $opts->{'renewalurl'} ne 'none') {
      $ENV{'NSRENEWALURL'} = $opts->{'renewalurl'};
   }
   if($opts->{'subjaltname'} ne 'none' && 
         $opts->{'subjaltname'} ne 'emailcopy') {
      if($opts->{'subjaltnametype'} eq 'ip') {
         $ENV{'SUBJECTALTNAMEIP'} = HELPERS::gen_subjectaltname_contents('IP:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'dns') {
         $ENV{'SUBJECTALTNAMEDNS'} = HELPERS::gen_subjectaltname_contents('DNS:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'mail') {
         $ENV{'SUBJECTALTNAMEEMAIL'} = HELPERS::gen_subjectaltname_contents('email:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'raw') {
         $ENV{'SUBJECTALTNAMERAW'} = HELPERS::gen_subjectaltname_contents(undef, $opts->{'subjaltname'});
      }
   }
   if($opts->{'extendedkeyusage'} ne 'none') { 
      $ENV{'EXTENDEDKEYUSAGE'} = $opts->{'extendedkeyusage'};
   }

   if(defined($opts->{'noemaildn'}) && $opts->{'noemaildn'}) {
      $cmd .= " -noemailDN";
   }

   # print STDERR "DEBUG call cmd: $cmd\n";
      
   my($rdfh, $wtfh);
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   $ext = "$cmd\n\n";
   while(<$rdfh>) {
      # print STDERR "DEBUG cmd returns: $_\n";
      $ext .= $_;
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(2, $ext);
      } elsif($_ =~ /There is already a certificate for/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(3, $ext);
      } elsif($_ =~ /bad ip address/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(4, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});
   $ENV{'NSSSLSERVERNAME'}     = 'dummy';
   $ENV{'NSREVOCATIONURL'}     = 'dummy';
   $ENV{'NSRENEWALURL'}        = 'dummy';
   $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
   $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
   $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
   $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';

   return($ret, $ext);
}

sub revoke {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $ret, $pid);

   $cmd = "$self->{'bin'} ca";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -revoke $opts->{'infile'}";

   if($opts->{'reason'} ne 'none') {
      $cmd .= " -crl_reason $opts->{'reason'}";
   }

   $ENV{'SSLPASS'} = $opts->{'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(2, $ext);
      } elsif($_ =~ /^ERROR:/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(3, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;
   
   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newreq {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $ret, $cmd, $pid);

   $cmd = "$self->{'bin'} req -new";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out $opts->{'outfile'}";
   $cmd .= " -key $opts->{'keyfile'}";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};
   print "DEBUG call: $cmd\n";
   
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);

   foreach(@{$opts->{'dn'}}) {
      print "DEBUG: add to dn: $_\n";
      if(defined($_)) {
         print $wtfh "$_\n";
      } else {
         print $wtfh ".\n";
      }
   }

   while(<$rdfh>) {
      $ext .= $_;
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   print "DEBUG return: $ext\n";
   
   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newcert {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $ret, $pid);

   $cmd = "$self->{'bin'} req -x509";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out \"$opts->{'outfile'}\"";
   $cmd .= " -key \"$opts->{'keyfile'}\"";
   $cmd .= " -in \"$opts->{'reqfile'}\"";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};

   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newcrl {
   my $self = shift;
   my $opts = { @_ };

   my ($out, $ext, $tmpfile, $cmd, $ret, $pid, $crl);

   $tmpfile = HELPERS::mktmp($self->{'tmp'}."/crl");
   $cmd = "$self->{'bin'} ca -gencrl";
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -config $opts->{'config'}";

   $cmd .= " -out $tmpfile";
   $cmd .= " -crldays $opts->{'crldays'}";

   $ENV{'SSLPASS'} = $opts->{ 'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   #print STDERR "DEBUG: cmd: $cmd";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      #print STDERR "DEBUG: cmd return: $_";
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(2, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $?>>8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext) if($ret);

   $crl = $self->parsecrl($tmpfile, 1);
   unlink( $tmpfile);

   $opts->{'format'} = 'PEM' if ( !defined( $opts->{ 'format'}));
   if($opts->{'format'} eq 'PEM') {
      $out = $crl->{'PEM'};
   } elsif ($opts->{'format'} eq 'DER') {
      $out = $crl->{'DER'};
   } elsif ($opts->{'format'} eq 'TXT') {
      $out = $crl->{'TXT'};
   } else {
      $out = $crl->{'PEM'};
   }

   unlink( $opts->{'outfile'});
   open(OUT, ">$opts->{'outfile'}") or return;
   print OUT $out;
   close OUT;

   return($ret, $ext);
}
   
sub parsecrl {
   my ($self, $file, $force) = @_;

   my $tmp   = {};
   my (@lines, $i, $t, $ext, $ret);

   # check if crl is cached
   if($self->{'CACHE'}->{$file} && not $force) {
      return($self->{'CACHE'}->{$file});
   }
   delete($self->{'CACHE'}->{$file});

   open(IN, $file) || do {
      $t = sprintf(_("Can't open CRL '%s': %s"), $file, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   # convert crl to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   ($ret, $tmp->{'TXT'}, $ext) = $self->convdata(
         'cmd'     => 'crl',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting CRL");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }
   
   ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
         'cmd'     => 'crl',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   if($ret) {
      $t = _("Error converting CRL");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   # get "normal infos"
   if ($tmp->{'TXT'}) {
      @lines = split(/\n/, $tmp->{'TXT'});
   } else {
      @lines = ();
   }
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Last Update.*: (.+)/i) {
         $tmp->{'LAST_UPDATE'} = $1;
      } elsif ($_ =~ /Next Update.*: (.+)/i) {
         $tmp->{'NEXT_UPDATE'} = $1;
      } 
   }   

   # get revoked certs
   $tmp->{'LIST'} = [];
   for($i = 0;
         ($i < scalar(@lines)) &&
         ($lines[$i] !~ /^[\s\t]*Revoked Certificates:$/i);
       $i++) {
      $self->{'CACHE'}->{$file} = $tmp;
      return($tmp) if ($lines[$i] =~ /No Revoked Certificates/i);
   }
   $i++;

   while($i < @lines) {
      if($lines[$i] =~ /Serial Number.*: (.+)/i) {
         my $t= {};
         $t->{'SERIAL'} = length($1)%2?"0".uc($1):uc($1);
         $i++;
         if($lines[$i] =~ /Revocation Date: (.*)/i ) {
            $t->{'DATE'} = $1;
            $i++;
            #print STDERR "read CRL: $t->{'SERIAL'}\n";
            push(@{$tmp->{'LIST'}}, $t);
         } else {
            $t = sprintf("CRL seems to be corrupt: %s\n", $file);
            GUI::HELPERS::print_warning($t);
            return;
         }
         
      } else {
         $i++;
      }
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub parsecert {
   my ($self, $crlfile, $indexfile, $file, $force) = @_;

   my $tmp   = {};
   my (@lines, $dn, $i, $c, $v, $k, $cmd, $crl, $time, $t, $ext, $ret, $pid);

   $time = time();

   $force && delete($self->{'CACHE'}->{$file});

   #print STDERR "DEBUG: got force $force\n";

   # check if certificate is cached
   if($self->{'CACHE'}->{$file}) {
      # print "DEBUG: use cached certificate $file\n";
      return($self->{'CACHE'}->{$file});
   }
   # print "DEBUG: parse certificate $file\n";

   open(IN, $file) || do {
      $t = sprintf("Can't open Certificate '%s': %s", $file, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   # convert certificate to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   ($ret, $tmp->{'TEXT'}, $ext) = $self->convdata(
         'cmd'     => 'x509',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting Certificate");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }
   
   ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
         'cmd'     => 'x509',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   if($ret) {
      $t = _("Error converting Certificate");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   foreach(@lines) {
      if($_ =~ /Serial Number.*: (.+) /i) {
         # shit, -text shows serial as decimal number :(
         # dirty fix (incompleted) --curly
         $i = sprintf( "%x", $1);
         $tmp->{'SERIAL'} = length($i)%2?"0".uc($i):uc($i);
      } elsif ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Not Before.*: (.+)/i) {
         $tmp->{'NOTBEFORE'} = $1;
      } elsif ($_ =~ /Not After.*: (.+)/i) {
         $tmp->{'NOTAFTER'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = $1;
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      }
   }   

   # parse subject DN
   $dn = HELPERS::parse_dn($tmp->{'DN'});
   foreach(keys(%$dn)) { 
      $tmp->{$_} = $dn->{$_};
   }

   # parse issuer DN
   $tmp->{'ISSUERDN'} = HELPERS::parse_dn($tmp->{'ISSUER'});

   # get extensions
   $tmp->{'EXT'} = HELPERS::parse_extensions(\@lines, "cert");

   # get fingerprint 
   $cmd = "$self->{'bin'} x509 -noout -fingerprint -md5 -in $file";
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTMD5'} = $v if($k =~ /MD5 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTMD5'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading fingerprint from Certificate");
      GUI::HELPERS::print_warning($t, $ext);
   }

   $cmd = "$self->{'bin'} x509 -noout -fingerprint -sha1 -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTSHA1'} = $v if($k =~ /SHA1 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTSHA1'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading fingerprint from Certificate");
      GUI::HELPERS::print_warning($t, $ext);
   }

   # get subject in openssl format
   $cmd = "$self->{'bin'} x509 -noout -subject -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      if($_ =~ /subject= (.*)/) {
         $tmp->{'SUBJECT'} = $1;
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading subject from Certificate");
      GUI::HELPERS::print_warning($t, $ext);
   }

   $tmp->{'EXPDATE'} = _get_date( $tmp->{'NOTAFTER'});

   if(defined($crlfile) && defined($indexfile)) {
      $crl = $self->parsecrl($crlfile, 1);
      #print STDERR "DEBUG: parsed crl $crlfile : $crl\n";

      defined($crl) || GUI::HELPERS::print_error(_("Can't read CRL"));
  
      $tmp->{'STATUS'} = _("VALID");
  
      if($tmp->{'EXPDATE'} < $time) {
         $tmp->{'STATUS'} = _("EXPIRED");
         # keep database up to date
         if($crl->{'ISSUER'} eq $tmp->{'ISSUER'}) {
            _set_expired($tmp->{'SERIAL'}, $indexfile);
         }
      }
     
      if (defined($tmp->{'SERIAL'})) {
         foreach my $revoked (@{$crl->{'LIST'}}) {
              #print STDERR "DEBUG: check tmp: $tmp->{'SERIAL'}\n";
              #print STDERR "DEBUG: check revoked: $revoked->{'SERIAL'}\n";
            next if ($tmp->{'SERIAL'} ne $revoked->{'SERIAL'});
            if ($tmp->{'SERIAL'} eq $revoked->{'SERIAL'}) {
               $tmp->{'STATUS'} = _("REVOKED");
            }
         }
      }
   } else {
      $tmp->{'STATUS'} = _("UNDEFINED");
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub parsereq {
   my ($self, $config, $file, $force) = @_;

   my $tmp    = {};

   my (@lines, $dn, $i, $c, $v, $k, $cmd, $t, $ext, $ret);

   # check if request is cached
   if($self->{'CACHE'}->{$file} && !$force) {
      # print STDERR "DEBUG return from CACHE $file\n";
      return($self->{'CACHE'}->{$file});
   } elsif($force) {
      # print STDERR "DEBUG delete from CACHE $file\n";
      delete($self->{'CACHE'}->{$file});
   } else {
      # print STDERR "DEBUG parse into CACHE $file\n";
   }

   open(IN, $file) || do {
      $t = sprintf(_("Can't open Request file %s: %s"), $file, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   # convert request to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);

   ($ret, $tmp->{'TEXT'}, $ext) = $self->convdata(
         'cmd'     => 'req',
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting Request");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
         'cmd'     => 'req',
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   if($ret) {
      $t = _("Error converting Request");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = $1;
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
         # print STDERR "read keysize: $tmp->{'KEYSIZE'}\n";
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      } elsif ($_ =~ /Version: \d.*/i) {
         $tmp->{'TYPE'} = 'PKCS#10';
      }
   }   

   $dn = HELPERS::parse_dn($tmp->{'DN'});
   foreach(keys(%$dn)) {
      $tmp->{$_} = $dn->{$_};
   }

   # get extensions
   $tmp->{'EXT'} = HELPERS::parse_extensions(\@lines, "req");

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub convdata {
   my $self = shift;
   my $opts = { @_ };
   
   my ($tmp, $ext, $ret, $file, $pid, $cmd);
   $file = HELPERS::mktmp($self->{'tmp'}."/data");

   $cmd = "$self->{'bin'} $opts->{'cmd'}";
   $cmd .= " -config $opts->{'config'}" if(defined($opts->{'config'}));
   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -out \"$file\"";
   if($opts->{'outform'} eq 'TEXT') {
      $cmd .= " -text -noout";
   } else {
      $cmd .= " -outform $opts->{'outform'}";
   }

   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   print $wtfh "$opts->{'data'}\n";
   while(<$rdfh>){
      $ext .= $_;
      # print STDERR "DEBUG: cmd ret: $_";
   };
   waitpid($pid, 0);
   $ret = $?>>8;

   if($self->{'broken'}) {
       if(($ret != 0 && $opts->{'cmd'} ne 'crl') ||
          ($ret != 0 && $opts->{'outform'} ne 'TEXT' && $opts->{'cmd'} eq 'crl') ||
          ($ret != 1 && $opts->{'outform'} eq 'TEXT' && $opts->{'cmd'} eq 'crl')) { 
          unlink($file);
          return($ret, undef, $ext);
       } else {
          $ret = 0;
       }
   } else { # wow, they fixed it :-)
      if($ret != 0) { 
         unlink($file); 
         return($ret, undef, $ext); 
      } else { 
         $ret = 0; 
      }
   }

   open(IN, $file) || do {
      my $t = sprintf(_("Can't open file %s: %s"), $file, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };
   $tmp .= $_ while(<IN>);
   close(IN);

   unlink($file);

   return($ret, $tmp, $ext);
}

sub convkey {
   my $self = shift;
   my $opts = { @_ };

   my ($tmp, $ext, $pid, $ret);
   my $file = HELPERS::mktmp($self->{'tmp'}."/key");

   my $cmd = "$self->{'bin'}";

   # print STDERR "DEBUG: got type: $opts->{'type'}\n";
  
   if($opts->{'type'} eq "RSA") {
      $cmd .= " rsa";
   } elsif($opts->{'type'} eq "DSA") {
      $cmd .= " dsa";
   }

   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -outform $opts->{'outform'}";
   $cmd .= " -in \"$opts->{'keyfile'}\"";
   $cmd .= " -out \"$file\"";

   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -passout env:SSLPASSOUT -des3" if(not $opts->{'nopass'});

   $ENV{'SSLPASS'}    = defined($opts->{'oldpass'}) ? $opts->{'oldpass'} :
                        $opts->{'pass'};
   $ENV{'SSLPASSOUT'} = $opts->{'pass'} if(not $opts->{'nopass'});
   
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'SSLPASSOUT'});
         return(1, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});
   delete($ENV{'SSLPASSOUT'});

   return(1, $ext) if($ret);

   open(IN, $file) || return(undef);
   $tmp .= $_ while(<IN>);
   close(IN);

   unlink($file);

   return($tmp);
}

sub genp12 {
   my $self = shift;
   my $opts = { @_ };

   my($cmd, $ext, $ret, $pid);
   
   $cmd = "$self->{'bin'} pkcs12 -export";
   $cmd .= " -out \"$opts->{'outfile'}\"";
   $cmd .= " -in \"$opts->{'certfile'}\"";
   $cmd .= " -inkey \"$opts->{'keyfile'}\"";
   if(not $opts->{'nopass'}) {
      $cmd .= " -passout env:P12PASS";
   } else {
      $cmd .= " -passout pass:";
   }
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -certfile $opts->{'cafile'}" if($opts->{'includeca'});
   $cmd .= " -nodes " if($opts->{'nopass'});
   $cmd .= " -name \"$opts->{'friendly'}\"" if($opts->{'friendly'} ne "");


   $ENV{'P12PASS'} = $opts->{'p12passwd'} if(not $opts->{'nopass'});
   $ENV{'SSLPASS'} = $opts->{'passwd'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /Error loading private key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'P12PASS'});
         return(1, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'P12PASS'});
   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub read_index {
   my ($self, $index) = @_;

   my (@lines, @index);
   
   open(IN, "<$index") || do {
      my $t = sprintf(_("Can't read index %s: %s"), $index, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };
   @lines = <IN>;
   close(IN);
   foreach my $l (@lines) {
      my $tmp = {};
      ($tmp->{'STATUS'},
       $tmp->{'EXPDATE'},
       $tmp->{'REVDATE'},
       $tmp->{'SERIAL'},
       $tmp->{'xxx'},
       $tmp->{'DN'}) = split(/\t/, $l);

      ($tmp->{'REVDATE'}, $tmp->{'REVREASON'}) = split(/,/, $tmp->{'REVDATE'});

      $tmp->{'EXPDATE'} = _get_index_date($tmp->{'EXPDATE'});
      if(defined($tmp->{'REVDATE'}) && ($tmp->{'REVDATE'} ne '')) {
         $tmp->{'REVDATE'} = _get_index_date( $tmp->{'REVDATE'});
      }

      push(@index, $tmp);
   }

   return(@index);
}

sub _set_expired {
   my ($serial, $index) =@_;
   
   open(IN, "<$index") || do {
      my $t = sprintf(_("Can't read index %s: %s"), $index, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   my @lines = <IN>;

   close IN;

   open(OUT, ">$index") || do {
      my $t = sprintf(_("Can't write index %s: %s"), $index, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   foreach my $l (@lines) {
      if($l =~ /\t$serial\t/) {
         $l =~ s/^V/E/;
      }
      print OUT $l;
   }

   close OUT;

   return;
}

sub _get_date {
   my $string = shift;
         
   $string =~ s/  / /g;
            
   my @t1 = split(/ /, $string);
   my @t2 = split(/:/, $t1[2]);

   $t1[0] = _get_index($t1[0]);
                              
   my $ret = Time::Local::timelocal($t2[2],$t2[1],$t2[0],$t1[1],$t1[0],$t1[3]);

   return($ret);
}

sub _get_index_date {
   my $string = shift;

   my ($y, $m, $d);
   
   $y = substr($string, 0, 2) + 2000;
   $m = substr($string, 2, 2) - 1;
   $d = substr($string, 4, 2);

   my $ret = Time::Local::timelocal(0, 0, 0, $d, $m, $y);

   return($ret);
}
   
sub _get_index {
   my $m = shift;

   my @a = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

   for(my $i = 0; $a[$i]; $i++) {
      return $i if($a[$i] eq $m);
   }
}
   
1
