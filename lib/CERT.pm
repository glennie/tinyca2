# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CERT.pm,v 1.11 2006/06/28 21:50:41 sm Exp $
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

package CERT;

use POSIX;

sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};

   $self->{'OpenSSL'} = shift;

   bless($self, $class);
}

#
# read certificates in directory into list
#
sub read_certlist {
   my ($self, $certdir, $crlfile, $indexfile, $force, $main) = @_;

   my($f, $certlist, $crl, $modt, $parsed, $tmp, $t, $c, $p, @files);

   GUI::HELPERS::set_cursor($main, 1);

   $certlist = [];
   
   $modt = (stat($certdir))[9];

   if(defined($self->{'lastread'}) &&
      ($self->{'lastread'} >= $modt) && 
      not defined($force)) {
      GUI::HELPERS::set_cursor($main, 0);
      return(0);
   }

   $crl = $self->{'OpenSSL'}->parsecrl($crlfile, $force);

   opendir(DIR, $certdir) || do {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(_("Can't open Certificate directory: %s"), $certdir);
      GUI::HELPERS::print_warning($t);
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      push(@files, $f);
      $c++;
   }

   $main->{'barbox'}->pack_start($main->{'progress'}, 0, 0, 0);
   $main->{'progress'}->show();
   foreach $f (@files) {
      next if $f =~ /^\./;

      $f =~ s/\.pem//;
      
      $tmp = HELPERS::dec_base64($f);
      next if not defined($tmp);
      next if $tmp eq "";

      if(defined($main)) {
         $t = sprintf(_("   Read Certificate: %s"), $tmp);
         GUI::HELPERS::set_status($main, $t);
         $p += 100/$c;
         if($p/100 <= 1) {
            $main->{'progress'}->set_fraction($p/100);
            while(Gtk2->events_pending) {
               Gtk2->main_iteration;
             }
         }
      }

      my $debugf = $certdir."/".$f.".pem";

      $parsed = $self->{'OpenSSL'}->parsecert($crlfile, $indexfile,
            $certdir."/".$f.".pem", $force);

      defined($parsed) || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_error(_("Can't read Certificate"));
      };

      $tmp .= "%".$parsed->{'STATUS'};

      push(@{$certlist}, $tmp);
   }
   @{$certlist} = sort(@{$certlist});
   closedir(DIR);

   $self->{'certlist'} = $certlist;

   $self->{'lastread'} = time();

   if(defined($main)) {
      $main->{'progress'}->set_fraction(0);
      $main->{'barbox'}->remove($main->{'progress'});
      GUI::HELPERS::set_cursor($main, 0);
   }

   return(1);  # got new list
}

#
# get information for renewing a certifikate
# 
sub get_renew_cert {
   my ($self, $main, $opts, $box) = @_;

   my ($cert, $status, $t, $ca, $cadir);

   $box->destroy() if(defined($box));

   if((not defined($opts->{'certfile'})) ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'certfile'} eq '') ||
      ($opts->{'passwd'} eq '')) {

      $cert = $main->{'certbrowser'}->selection_dn();
   
      if(not defined($cert)) {
         GUI::HELPERS::print_info(_("Please select a Certificate first"));
         return;
      }
   
      $ca     = $main->{'certbrowser'}->selection_caname();
      $cadir  = $main->{'certbrowser'}->selection_cadir();
      $status = $main->{'certbrowser'}->selection_status();
   
      if($status eq _("VALID")) {
         $t = sprintf(
               _("Can't renew Certifikate with Status: %s\nPlease revoke the Certificate first"), 
               $status);
         GUI::HELPERS::print_warning($t);
         return;
      } 

      $opts->{'certname'} = HELPERS::enc_base64($cert);
      $opts->{'reqname'} = $opts->{'certname'};
      $opts->{'certfile'} = $cadir."/certs/".$opts->{'certname'}.".pem";
      $opts->{'keyfile'}  = $cadir."/keys/".$opts->{'certname'}.".pem";
      $opts->{'reqfile'}  = $cadir."/req/".$opts->{'certname'}.".pem";

      if((not -s $opts->{'certfile'}) ||
         (not -s $opts->{'keyfile'})  ||
         (not -s $opts->{'reqfile'})) {
         $t = _("Key and Request are necessary for renewal of a Certificate\nRenewal is not possible!");
         GUI::HELPERS::print_warning($t);
         return;
      }
   
      $main->show_req_sign_dialog($opts);
      return;
   }

   $main->{'REQ'}->sign_req($main, $opts);
   
   return;
}

#
# get information for revoking a certifikate
# 
sub get_revoke_cert {
   my ($self, $main, $opts, $box) = @_;

   my ($cert, $status, $t, $ca, $cadir);

   $box->destroy() if(defined($box));

   if((not defined($opts->{'certfile'})) ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'certfile'} eq '') ||
      ($opts->{'passwd'} eq '')) {
      $opts->{'certfile'} = $main->{'certbrowser'}->selection_fname();
   
      if(not defined($opts->{'certfile'})) {
         $t = _("Please select a Certificate first");
         GUI::HELPERS::print_info($t);
         return;
      }
   
      $ca     = $main->{'certbrowser'}->selection_caname();
      $cadir  = $main->{'certbrowser'}->selection_cadir();
      $cert   = $main->{'certbrowser'}->selection_dn();
      $status = $main->{'certbrowser'}->selection_status();
   
      if($status ne _("VALID")) {
         $t = sprintf(_("Can't revoke Certifikate with Status: %s"), 
               $status);
         GUI::HELPERS::print_warning($t);
         return;
      }
   
      $opts->{'certname'} = HELPERS::enc_base64($cert);
      $opts->{'cert'} = $cert;
   
      $main->show_cert_revoke_dialog($opts);
      return;
   }

   $self->revoke_cert($main, $opts);
   
   return;
}

#
# now really revoke the certificate
#
sub revoke_cert {
   my ($self, $main, $opts) = @_;

   my($ca, $cadir, $ret, $t, $ext, $reason);

   $ca    = $main->{'certbrowser'}->selection_caname();
   $cadir = $main->{'certbrowser'}->selection_cadir();

   GUI::HELPERS::set_cursor($main, 1);

   if(defined($opts->{'reason'}) && $opts->{'reason'} ne '') {
      $reason = $opts->{'reason'};
   } else {
      $reason = 'none';
   }

   ($ret, $ext) = $self->{'OpenSSL'}->revoke(
         'config' => $main->{'CA'}->{$ca}->{'cnf'},
         'infile' => $cadir."/certs/".$opts->{'certname'}.".pem",
         'pass'   => $opts->{'passwd'},
         'reason' => $reason
         );

   if($ret eq 1) {
      GUI::HELPERS::set_cursor($main, 0);
      $t = _("Wrong CA password given\nRevoking the Certificate failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 2) {
      GUI::HELPERS::set_cursor($main, 0);
      $t = _("CA Key not found\nRevoking the Certificate failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret) {
      GUI::HELPERS::set_cursor($main, 0);
      $t = _("Revoking the Certificate failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   }

   ($ret, $ext) = $self->{'OpenSSL'}->newcrl(
         'config'  => $main->{'CA'}->{$ca}->{'cnf'},
         'pass'    => $opts->{'passwd'},
         'crldays' => 365,
         'outfile' => $cadir."/crl/crl.pem"
         );

   if (not -s $cadir."/crl/crl.pem" || $ret) { 
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;

      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(
            _("Generating a new Revocation List failed"), $ext);
   }

   $self->{'OpenSSL'}->parsecrl( $cadir."/crl/crl.pem", 1);

   $self->reread_cert($main, $opts->{'cert'});

   # force reread of certlist
   $main->{'certbrowser'}->update($cadir."/certs",
                                  $cadir."/crl/crl.pem",
                                  $cadir."/index.txt",
                                  0);

   GUI::HELPERS::set_cursor($main, 0);

   delete($opts->{$_}) foreach(keys(%$opts));
   $opts = undef;

   return;
}

#
# get name of certificatefile to delete
#
sub get_del_cert {
   my ($self, $main) = @_;
    
   my($certname, $cert, $certfile, $status, $t, $cadir, $ca);

   $certfile = $main->{'certbrowser'}->selection_fname();

   if(not defined $certfile) {
      GUI::HELPERS::print_info(_("Please select a Certificate first"));
      return;
   }

   $ca     = $main->{'certbrowser'}->selection_caname();
   $cadir  = $main->{'certbrowser'}->selection_cadir();
   $cert   = $main->{'certbrowser'}->selection_dn();
   $status = $main->{'certbrowser'}->selection_status();

   $certname = HELPERS::enc_base64($cert);

   if($status eq _("VALID")) {
      GUI::HELPERS::print_warning(
            _("Can't delete VALID certificate!\nPlease revoke the Certificate first."));
      return;
   }

   $main->show_del_confirm($certfile, 'cert');

   return;
}

#
# now really delete the certificatefile
#
sub del_cert {
   my ($self, $main, $file) = @_;

   GUI::HELPERS::set_cursor($main, 1);

   unlink($file);

   my $cadir = $main->{'certbrowser'}->selection_cadir();

   $main->{'certbrowser'}->update($cadir."/certs",
                                  $cadir."/crl/crl.pem",
                                  $cadir."/index.txt",
                                  0);

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

#
# get informations for exporting a certificate
#
sub get_export_cert {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my($ca, $t, $cn, $email, $cadir);

   if(not defined($opts)) {
      $cn    = $main->{'certbrowser'}->selection_cn();
      $email = $main->{'certbrowser'}->selection_email();
   
      if(not defined $cn) {
         GUI::HELPERS::print_info(_("Please select a Certificate first"));
         return;
      }

      $ca    = $main->{'certbrowser'}->selection_caname();
      $cadir = $main->{'certbrowser'}->selection_cadir();

      $opts->{'status'} = $main->{'certbrowser'}->selection_status();
      $opts->{'cert'}   = $main->{'certbrowser'}->selection_dn();

      $opts->{'certname'} = HELPERS::enc_base64($opts->{'cert'});
      $opts->{'certfile'} = $cadir."/certs/".$opts->{'certname'}.".pem";
      $opts->{'keyfile'}  = $cadir."/keys/".$opts->{'certname'}.".pem";
      $opts->{'cafile'}   = $cadir."/cacert.pem";

      if (-f $cadir."/cachain.pem") {
         $opts->{'cafile'} = $cadir."/cachain.pem";
      }

      if($opts->{'status'} ne _("VALID")) {
         $t = _("Certificate seems not to be VALID");
         $t .= "\n";
         $t .= _("Export is not possible");
         GUI::HELPERS::print_warning($t);
         return;
      }
      
      $opts->{'parsed'} = $self->parse_cert($main, $opts->{'certname'});

      if((defined($email)) && $email ne '' && $email ne ' ') {
         $opts->{'outfile'} = "$main->{'exportdir'}/$email-cert.pem";
      }elsif((defined($cn)) && $cn ne '' && $cn ne ' ') {
         $opts->{'outfile'} = "$main->{'exportdir'}/$cn-cert.pem";
      }else{
         $opts->{'outfile'} = "$main->{'exportdir'}/cert.pem";
      }
      $opts->{'format'}       = 'PEM';
      $opts->{'include'}      = 0;
      $opts->{'incfp'}        = 0;
      $opts->{'nopass'}       = 0;
      $opts->{'friendlyname'} = '';

      $main->show_export_dialog($opts, 'cert');
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) {
      $main->show_export_dialog($opts, 'cert');
      GUI::HELPERS::print_warning(
            _("Please give at least the output file"));
      return;
   }

   if($opts->{'format'} eq 'P12') {
      if(not -s $opts->{'keyfile'}) {
         $t = _("Key is necessary for export as PKCS#12");
         $t .= "\n";
         $t .= _("Export is not possible!");
         GUI::HELPERS::print_warning($t);
         return;
      }

      if((not defined($opts->{'p12passwd'})) &&
            (not $opts->{'nopass'})) {
         $opts->{'includeca'} = 1;
         $main->show_p12_export_dialog($opts, 'cert');
         return;
      }
   } elsif(($opts->{'format'} eq 'ZIP') || ($opts->{'format'} eq 'TAR')) {
      if(not -s $opts->{'keyfile'}) {
         $t = sprintf(
               _("Key is necessary for export as %s"), $opts->{'format'});
         $t .= "\n";
         $t .= _("Export is not possible!");
         GUI::HELPERS::print_warning($t);
         return;
      }
   }

   $self->export_cert($main, $opts); #FIXME no need for two functions

   return;
}


#
# now really export the certificate
#
sub export_cert {
   my ($self, $main, $opts) = @_;
    
   my($ca, $t, $out, $ret, $ext);

   GUI::HELPERS::set_cursor($main, 1);

   $ca   = $main->{'CA'}->{'actca'};

   if($opts->{'format'} eq 'PEM') {
      if($opts->{'incfp'}) {
         $out = '';
         $out .= "Fingerprint (MD5): $opts->{'parsed'}->{'FINGERPRINTMD5'}\n";
         $out .= "Fingerprint (SHA1): $opts->{'parsed'}->{'FINGERPRINTSHA1'}\n\n";
      } else {
         $out = '';
      }

      $out .= $opts->{'parsed'}->{'PEM'};

      if($opts->{'include'}) {
         open(IN, "<$opts->{'keyfile'}") || do {
            GUI::HELPERS::set_cursor($main, 0);
            $t = sprintf(_("Can't open Certificate file: %s: %s"),
                  $opts->{'keyfile'}, $!);
            return;
         };
         $out .= "\n";
         $out .= $_ while(<IN>);
         close(IN);
      }
   } elsif ($opts->{'format'} eq 'DER') {
      $out = $opts->{'parsed'}->{'DER'};
   } elsif ($opts->{'format'} eq 'TXT') {
      $out = $opts->{'parsed'}->{'TEXT'};
   } elsif ($opts->{'format'} eq 'P12') {
      unlink($opts->{'outfile'});
      ($ret, $ext) = $self->{'OpenSSL'}->genp12(
            certfile  => $opts->{'certfile'},
            keyfile   => $opts->{'keyfile'},
            cafile    => $opts->{'cafile'},
            outfile   => $opts->{'outfile'},
            passwd    => $opts->{'passwd'},
            p12passwd => $opts->{'p12passwd'},
            includeca => $opts->{'includeca'},
            nopass    => $opts->{'nopass'},
            friendly  => $opts->{'friendlyname'}
            );

      GUI::HELPERS::set_cursor($main, 0);

      if($ret eq 1) {
         $t = "Wrong password given\nDecrypting Key failed\nGenerating PKCS#12 failed";
         GUI::HELPERS::print_warning($t, $ext);
         return;
      } elsif($ret || (not -s $opts->{'outfile'})) {
         $t = _("Generating PKCS#12 failed");
         GUI::HELPERS::print_warning($t, $ext);
         return;
      }

      $main->{'exportdir'} = HELPERS::write_export_dir($main, 
            $opts->{'outfile'});

      $t = sprintf(_("Certificate and Key successfully exported to %s"), 
            $opts->{'outfile'});
      GUI::HELPERS::print_info($t, $ext);
      return;

   } elsif (($opts->{'format'} eq "ZIP") || ($opts->{'format'} eq "TAR")) {

      my $tmpcert   = "$main->{'tmpdir'}/cert.pem";
      my $tmpkey    = "$main->{'tmpdir'}/key.pem";
      my $tmpcacert = "$main->{'tmpdir'}/cacert.pem";

      open(OUT, ">$tmpcert") || do {
         GUI::HELPERS::set_cursor($main, 0);
         $t = sprintf(_("Can't create temporary file: %s: %s"), 
               $tmpcert, $!);
         GUI::HELPERS::print_warning($t);
         return;
      };
      print OUT $opts->{'parsed'}->{'PEM'};
      close OUT;

      # store key in temporary location
      {
      open(IN, "<$opts->{'keyfile'}") || do {
         GUI::HELPERS::set_cursor($main, 0);
         $t = sprintf(_("Can't read Key file: %s: %s"), $tmpcert, $!);
         GUI::HELPERS::print_warning($t);
         return;
      };
      my @key = <IN>;
      close IN;

      open(OUT, ">$tmpkey") || do {
         GUI::HELPERS::set_cursor($main, 0);
         $t = sprintf(_("Can't create temporary file: %s: %s"), 
               $tmpcert, $!);
         GUI::HELPERS::print_warning($t);
         return;
      };
      print OUT @key;
      close OUT;
      }

      # store cacert in temporary location
      {
      open(IN, "<$opts->{'cafile'}") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't read CA certificate"));
         return;
      };
      my @cacert = <IN>;
      close IN;

      open(OUT, ">$tmpcacert") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(_("Can't create temporary file"));
         return;
      };
      print OUT @cacert;
      close OUT;
      }

      unlink($opts->{'outfile'});
      if($opts->{'format'} eq "ZIP") {
         system($main->{'init'}->{'zipbin'}, '-j', $opts->{'outfile'},
               $tmpcacert, $tmpkey, $tmpcert); 
         my $ret = $? >> 8;
      } elsif ($opts->{'format'} eq "TAR") {
         system($main->{'init'}->{'tarbin'}, 'cfv', $opts->{'outfile'},
               $tmpcacert, $tmpkey, $tmpcert); 
      }

      GUI::HELPERS::set_cursor($main, 0);

      if(not -s $opts->{'outfile'} || $ret) {
         GUI::HELPERS::print_warning(
               sprintf(_("Generating %s file failed"), $opts->{'format'})
               );
      } else {
         $main->{'exportdir'} = HELPERS::write_export_dir($main, 
               $opts->{'outfile'});

         $t = sprintf(
               _("Certificate and Key successfully exported to %s"), 
               $opts->{'outfile'});
         GUI::HELPERS::print_info($t);
      unlink($tmpcacert);
      unlink($tmpcert);
      unlink($tmpkey);

      return;
      }

   } else {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(_("Invalid Format for export_cert(): %s"), 
            $opts->{'format'});
      GUI::HELPERS::print_warning($t);
      return;
   }

   GUI::HELPERS::set_cursor($main, 0);

   open(OUT, ">$opts->{'outfile'}") || do {
      GUI::HELPERS::print_warning(_("Can't open output file: %s: %s"),
            $opts->{'outfile'}, $!);
      return;
   };

   print OUT $out;
   close OUT;

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});
   
   $t = sprintf(_("Certificate successfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t);

   return;
}

sub reread_cert {
   my ($self, $main, $name) = @_;

   my ($parsed, $tmp);

   GUI::HELPERS::set_cursor($main, 1);

   $name = HELPERS::enc_base64($name);
      
   $parsed = $self->parse_cert($main, $name, 1);

   # print STDERR "DEBUG: status $parsed->{'STATUS'}\n";

   foreach(@{$self->{'certlist'}}) {
      if(/^$name%/) {
         ; #delete
      } else {
         push(@{$tmp}, $_);
      }
   }
   push(@{$tmp}, $name."%".$parsed->{'STATUS'});
   @{$tmp} = sort(@{$tmp});

   delete($self->{'certlist'});
   $self->{'certlist'} = $tmp;

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

sub parse_cert {
   my ($self, $main, $name, $force) = @_;

   my($ca, $certfile, $x509, $parsed);

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $main->{'CA'}->{'actca'};

   if($name eq 'CA') {
      $certfile = $main->{'CA'}->{$ca}->{'dir'}."/cacert.pem";
   } else {
      $certfile = $main->{'CA'}->{$ca}->{'dir'}."/certs/".$name.".pem";
   }

   $parsed = $self->{'OpenSSL'}->parsecert( 
         $main->{'CA'}->{$ca}->{'dir'}."/crl/crl.pem", 
         $main->{'CA'}->{$ca}->{'dir'}."/index.txt",
         $certfile,
         $force
         );

   GUI::HELPERS::set_cursor($main, 0);

   return($parsed);
}

1
