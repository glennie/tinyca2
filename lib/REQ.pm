# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: REQ.pm,v 1.7 2006/06/28 21:50:42 sm Exp $
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

package REQ;

use POSIX;

sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};

   $self->{'OpenSSL'} = shift;

   bless($self, $class);
}

#
# check if all data for creating a new request is available
#
sub get_req_create {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($name, $action, $parsed, $reqfile, $keyfile, $ca, $t);

   $ca   = $main->{'CA'}->{'actca'};

   if(!(defined($opts)) || !(ref($opts))) {
      if(defined($opts) && $opts eq "signserver") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "server";
      } elsif(defined($opts) && $opts eq "signclient") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "client";
      } elsif (defined($opts)) {
         $t = sprintf(_("Strange value for 'opts': %s"), $opts);
         GUI::HELPERS::print_error($t);
      }
      $opts->{'bits'}   = 4096;
      $opts->{'digest'} = 'sha1';
      $opts->{'algo'}   = 'rsa';
      if(defined($opts) && $opts eq "sign") {
         $opts->{'sign'} = 1;
      }
   
      $parsed = $main->{'CERT'}->parse_cert($main, 'CA');
      
      defined($parsed) || 
         GUI::HELPERS::print_error(_("Can't read CA certificate"));
   
      # set defaults
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
      my $cc = 0;
      foreach my $ou (@{$parsed->{'OU'}}) {
         $opts->{'OU'}->[$cc++] = $ou;
      }

      $main->show_req_dialog($opts);
      return;
   }

   if((not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) {
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(
            _("Please specify at least Common Name ")
            ._("and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
       $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(_("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if((defined $opts->{'C'}) &&
      ($opts->{'C'} ne "") &&
      (length($opts->{'C'}) != 2)) {
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(
            _("Country must be exact 2 letter code"));
      return;
   }

   $name = HELPERS::gen_name($opts);

   $opts->{'reqname'} = HELPERS::enc_base64($name);

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'reqname'}.".pem";

   if(-s $reqfile || -s $keyfile) {
      $main->show_req_overwrite_warning($opts);
      return;
   }

   $self->create_req($main, $opts);

   return;
}

#
# create new request and key
#
sub create_req {
   my ($self, $main, $opts) = @_;

   my($reqfile, $keyfile, $ca, $ret, $ext, $cadir);

   GUI::HELPERS::set_cursor($main, 1);
   
   $ca    = $main->{'CA'}->{'actca'};
   $cadir = $main->{'CA'}->{$ca}->{'dir'};

   $reqfile = $cadir."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $cadir."/keys/".$opts->{'reqname'}.".pem";
         
   ($ret, $ext) = $self->{'OpenSSL'}->newkey(
         'algo'    => $opts->{'algo'},
         'bits'    => $opts->{'bits'},
         'outfile' => $keyfile,
         'pass'    => $opts->{'passwd'}
         );

   if (not -s $keyfile || $ret) { 
      unlink($keyfile);
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Generating key failed"), $ext);
      return;
   }

   my @dn = ( $opts->{'C'}, $opts->{'ST'}, $opts->{'L'}, $opts->{'O'} );
   if(ref($opts->{'OU'})) {
      foreach my $ou (@{$opts->{'OU'}}) {
      	push(@dn,$ou);
      }
   } else {
      push(@dn, $opts->{'OU'});
   }
   @dn = (@dn, $opts->{'CN'}, $opts->{'EMAIL'}, '', '');
   ($ret, $ext) = $self->{'OpenSSL'}->newreq(
         'config'   => $main->{'CA'}->{$ca}->{'cnf'},
         'outfile'  => $reqfile,
         'keyfile'  => $keyfile,
         'digest'   => $opts->{'digest'},
         'pass'     => $opts->{'passwd'},
         'dn'       => \@dn,
         );

   if (not -s $reqfile || $ret) { 
      unlink($keyfile);
      unlink($reqfile);
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Generating Request failed"), $ext);
      return;
   }

   my $parsed = $self->parse_req($main, $opts->{'reqname'}, 1);

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0); 

   $main->{'keybrowser'}->update($cadir."/keys",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   GUI::HELPERS::set_cursor($main, 0);

   if($opts->{'sign'}) {
      $opts->{'reqfile'} = $reqfile;
      $opts->{'passwd'}  = undef; # to sign request, ca-password is needed
      $self->get_sign_req($main, $opts);
   }

   return;
}

#
# get name of requestfile to delete
#
sub get_del_req {
   my ($self, $main) = @_;

   my($reqname, $req, $reqfile, $row, $ind, $ca, $cadir);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($reqfile))) {
      $req = $main->{'reqbrowser'}->selection_dn(); 


      if(not defined($req)) {
         GUI::HELPERS::print_info(_("Please select a Request first"));
         return;
      }

      $reqname = HELPERS::enc_base64($req);
      $reqfile = $cadir."/req/".$reqname.".pem";

   }

   if(not -s $reqfile) {
      GUI::HELPERS::print_warning(_("Request file not found"));
      return;
   }

   $main->show_del_confirm($reqfile, 'req');

   return;
}

#
# now really delete the requestfile
#
sub del_req {
   my ($self, $main, $file) = @_;

   my ($ca, $cadir);

   GUI::HELPERS::set_cursor($main, 1);

   unlink($file);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0); 

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

sub read_reqlist {
   my ($self, $reqdir, $crlfile, $indexfile, $force, $main) = @_;

   my ($f, $modt, $d, $reqlist, $c, $p, $t);

   GUI::HELPERS::set_cursor($main, 1);

   $reqlist = [];

   $modt = (stat($reqdir))[9];

   if(defined($self->{'lastread'}) &&
      $self->{'lastread'} >= $modt) {  
      GUI::HELPERS::set_cursor($main, 0);
      return(0);
   }

   opendir(DIR, $reqdir) || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Can't open Request directory"));
      return(0);
   };

   while($f = readdir(DIR)) { 
      next if $f =~ /^\./;
      $c++;
   }
   rewinddir(DIR);

   $main->{'barbox'}->pack_start($main->{'progress'}, 0, 0, 0);
   $main->{'progress'}->show();
   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $d = HELPERS::dec_base64($f);
      next if not defined($d);
      next if $d eq "";
      push(@{$reqlist}, $d);

      if(defined($main)) {
         $t = sprintf(_("   Read Request: %s"), $d);
         GUI::HELPERS::set_status($main, $t);
         $p += 100/$c;
         if($p/100 <= 1) {
            $main->{'progress'}->set_fraction($p/100);
            while(Gtk2->events_pending) {
               Gtk2->main_iteration;
            }
         }
         select(undef, undef, undef, 0.025);
      }
   }
   @{$reqlist} = sort(@{$reqlist});
   closedir(DIR);

   delete($self->{'reqlist'});
   $self->{'reqlist'} = $reqlist;

   $self->{'lastread'} = time();

   if(defined($main)) {
      $main->{'progress'}->set_fraction(0);
      $main->{'barbox'}->remove($main->{'progress'});
      GUI::HELPERS::set_cursor($main, 0);
   }

   return(1);  # got new list
}

#
# get name of request to sign
#
sub get_sign_req {
   my ($self, $main, $opts, $box) = @_;

   my($time, $parsed, $ca, $cadir, $ext, $ret);

   $box->destroy() if(defined($box));
   
   $time  = time();
   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($opts->{'reqfile'}))) {
      $opts->{'req'} = $main->{'reqbrowser'}->selection_dn(); 

      if(not defined($opts->{'req'})) {
         GUI::HELPERS::print_info(_("Please select a Request first"));
         return;
      }

      $opts->{'reqname'} = HELPERS::enc_base64($opts->{'req'});
      $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";
   }

   if(not -s $opts->{'reqfile'}) {
         GUI::HELPERS::print_warning(_("Request file not found"));
         return;
   }
   
   if((-s $cadir."/certs/".$opts->{'reqname'}.".pem") &&
      (!(defined($opts->{'overwrite'})) || ($opts->{'overwrite'} ne 'true'))) {
      $main->show_cert_overwrite_confirm($opts);
      return;
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   defined($parsed) || 
      GUI::HELPERS::print_error(_("Can't read CA certificate"));

   if(!defined($opts->{'passwd'})) {
      $opts->{'days'} =
         $main->{'TCONFIG'}->{$opts->{'type'}."_ca"}->{'default_days'};

      if($opts->{'days'} > (($parsed->{'EXPDATE'}/86400) - ($time/86400))) {
         $opts->{'days'} = int(($parsed->{'EXPDATE'}/86400) - ($time/86400));
      }

      $main->show_req_sign_dialog($opts); 
      return; 
   }

   if((($time + ($opts->{'days'} * 86400)) > $parsed->{'EXPDATE'}) &&
      (!(defined($opts->{'ignoredate'})) || 
       $opts->{'ignoredate'} ne 'true')){
      $main->show_req_date_warning($opts);
      return;
   }

   # try to find message digest used for the request
   $parsed = undef;
   $parsed = $self->parse_req($main, $opts->{'reqname'}, 1);
   defined($parsed) ||
      GUI::HELPERS::print_error(_("Can't read Request file"));

   if(defined($parsed->{'SIG_ALGORITHM'})) {
      $opts->{'digest'} = $parsed->{'SIG_ALGORITHM'};

      if($opts->{'digest'} =~ /^md2/) {
         $opts->{'digest'} = "md2";
      } elsif ($opts->{'digest'} =~ /^mdc2/) {
         $opts->{'digest'} = "mdc2";
      } elsif ($opts->{'digest'} =~ /^md4/) {
         $opts->{'digest'} = "md4";
      } elsif ($opts->{'digest'} =~ /^md5/) {
         $opts->{'digest'} = "md5";
      } elsif ($opts->{'digest'} =~ /^sha1/) {
         $opts->{'digest'} = "sha1";
      } elsif ($opts->{'digest'} =~ /^ripemd160/) {
         $opts->{'digest'} = "ripemd160";
      } else {
      }
   } else { 
      $opts->{'digest'} = 0;
   }

   ($ret, $ext) = $self->sign_req($main, $opts);

   return($ret, $ext);
}

#
# now really sign the request
#
sub sign_req {
   my ($self, $main, $opts) = @_;

   my($serial, $certout, $certfile, $certfile2, $ca, $cadir, $ret, $t, $ext);

   GUI::HELPERS::set_cursor($main, 1);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $serial = $cadir."/serial";
   open(IN, "<$serial") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Can't read serial"));
      return;
   };
   $serial = <IN>;
   chomp($serial);
   close IN;

   if(not defined($opts->{'nsSslServerName'})) {
      $opts->{'nsSslServerName'} = 'none';
   }
   if(not defined($opts->{'nsRevocationUrl'})) {
      $opts->{'nsRevocationUrl'} = 'none';
   }
   if(not defined($opts->{'nsRenewalUrl'})) {
      $opts->{'nsRenewalUrl'} = 'none';
   }
   if(not defined($opts->{'subjectAltName'})) {
      $opts->{'subjectAltName'}     = 'none';
      $opts->{'subjectAltNameType'} = 'none';
   } else {
       $opts->{'subjectAltNameType'} = 
          $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'subjectAltNameType'};
   }
   if(not defined($opts->{'extendedKeyUsage'})) {
      $opts->{'extendedKeyUsage'}     = 'none';
      $opts->{'extendedKeyUsageType'} = 'none';
   } else {
      $opts->{'extendedKeyUsageType'} = 
         $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'extendedKeyUsageType'};
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'mode'                 => $opts->{'mode'},
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'keyfile'              => $opts->{'keyfile'},
            'cacertfile'           => $opts->{'cacertfile'},
            'outdir'               => $opts->{'outdir'},
            'days'                 => $opts->{'days'},
            'parentpw'             => $opts->{'parentpw'},
            'caname'               => "ca_ca",
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'},
            'digest'               => $opts->{'digest'}
            );
   } else {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'days'                 => $opts->{'days'},
            'pass'                 => $opts->{'passwd'},
            'caname'               => $opts->{'type'}."_ca",
            'sslservername'        => $opts->{'nsSslServerName'},
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'},
            'digest'               => $opts->{'digest'}
            );
   }

   GUI::HELPERS::set_cursor($main, 0);

   if($ret eq 1) {
      $t = _("Wrong CA password given\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 2) {
      $t = _("CA Key not found\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 3) {
      $t = _("Certificate already existing\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 4) {
      $t = _("Invalid IP Address given\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret) {
      GUI::HELPERS::print_warning(
            _("Signing of the Request failed"), $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return($ret, $ext);
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $opts->{'outfile'};
      $certfile2 = $cadir."/certs/".$opts->{'reqname'}.".pem";
   } else {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $cadir."/certs/".$opts->{'reqname'}.".pem";
      #print STDERR "DEBUG: write certificate to: ".$cadir."/certs/".$opts->{'reqname'}.".pem";
   }

   if (not -s $certout) {
         GUI::HELPERS::print_warning(
               _("Signing of the Request failed"), $ext);
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
   }

   open(IN, "<$certout") || do {
      GUI::HELPERS::print_warning(_("Can't read Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   open(OUT, ">$certfile") || do {
      GUI::HELPERS::print_warning(_("Can't write Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   print OUT while(<IN>);

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      close OUT;
      open(OUT, ">$certfile2") || do {
         GUI::HELPERS::print_warning(_("Can't write Certificate file"));
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
      };
      seek(IN, 0, 0);
      print OUT while(<IN>);
   }
   
   close IN; close OUT;

   GUI::HELPERS::print_info(
         _("Request signed succesfully.\nCertificate created"), $ext);
   
   GUI::HELPERS::set_cursor($main, 1);

   $main->{'CERT'}->reread_cert($main, 
         HELPERS::dec_base64($opts->{'reqname'}));
   
   $main->{'certbrowser'}->update($cadir."/certs",
                                  $cadir."/crl/crl.pem",
                                  $cadir."/index.txt",
                                  0);

   delete($opts->{$_}) foreach(keys(%$opts));
   $opts = undef;

   GUI::HELPERS::set_cursor($main, 0);
     
   return($ret, $ext);
}

#
# get informations/verifications to import request from file
#
sub get_import_req {
   my ($self, $main, $opts, $box) = @_;

   my ($ret, $ext, $der);

   $box->destroy() if(defined($box));

   my($ca, $parsed, $file, $format);

   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $main->show_req_import_dialog();
      return;
   }

   if(not defined($opts->{'infile'})) {
      $main->show_req_import_dialog();
      GUI::HELPERS::print_warning(_("Please select a Request file first"));
      return;
   }
   if(not -s $opts->{'infile'}) {
      $main->show_req_import_dialog();
      GUI::HELPERS::print_warning(
            _("Can't find Request file: ").$opts->{'infile'});
      return;
   }

   open(IN, "<$opts->{'infile'}") || do {
      GUI::HELPERS::print_warning(
            _("Can't read Request file:").$opts->{'infile'});
      return;
   };

   $opts->{'in'} .= $_ while(<IN>);

   if($opts->{'in'} =~ /-BEGIN[\s\w]+CERTIFICATE REQUEST-/i) {
      $format = "PEM";
      $file = $opts->{'infile'};
   } else {
      $format = "DER";
   }

   if($format eq "DER") {
      ($ret, $der, $ext) = $opts->{'in'} = $self->{'OpenSSL'}->convdata(
            'cmd'     => 'req',
            'data'    => $opts->{'in'},
            'inform'  => 'DER',
            'outform' => 'PEM'
            );

      if($ret) {
         GUI::HELPERS::print_warning(
               _("Error converting Request"), $ext);
         return;
      }

      $opts->{'tmpfile'} = 
         HELPERS::mktmp($self->{'OpenSSL'}->{'tmp'}."/import");
   
      open(TMP, ">$opts->{'tmpfile'}") || do {
         GUI::HELPERS::print_warning( _("Can't create temporary file: %s: %s"),
               $opts->{'tmpfile'}, $!);
         return;
      };
      print TMP $opts->{'in'};
      close(TMP);
      $file = $opts->{'tmpfile'};
   }

   $parsed = $self->{'OpenSSL'}->parsereq(
			$main->{'CA'}->{$ca}->{'cnf'},
			$file);
   
   if(not defined($parsed)) {
      unlink($opts->{'tmpfile'});
      GUI::HELPERS::print_warning(_("Parsing Request failed"));
      return;
   }
   
   $main->show_import_verification("req", $opts, $parsed);
   return;
}

#
# import request
#
sub import_req {
   my ($self, $main, $opts, $parsed, $box) = @_;

   my ($ca, $cadir);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);
   
   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $opts->{'name'} = HELPERS::gen_name($parsed);
   
   $opts->{'reqname'} = HELPERS::enc_base64($opts->{'name'});

   $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";

   open(OUT, ">$opts->{'reqfile'}") || do {
      unlink($opts->{'tmpfile'});
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(_("Can't open output file: %s: %s"),
            $opts->{'reqfile'}, $!);
      return;
   };
   print OUT $opts->{'in'};
   close OUT;

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

sub parse_req {
   my ($self, $main, $name, $force) = @_;
   
   my ($parsed, $ca, $reqfile, $req);

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $main->{'CA'}->{'actca'};

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$name.".pem";

   $parsed = $self->{'OpenSSL'}->parsereq($main->{'CA'}->{$ca}->{'cnf'},
         $reqfile, $force);

   GUI::HELPERS::set_cursor($main, 0);

   return($parsed);
}

1

