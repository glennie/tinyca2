# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: KEY.pm,v 1.8 2006/06/28 21:50:41 sm Exp $
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

package KEY;

use POSIX;

sub new {
   my $self = {};
   my $that = shift;
   my $class = ref($that) || $that;

   bless($self, $class);
}

#
# get name of keyfile to delete
#
sub get_del_key {
   my ($self, $main) = @_;

   my($keyname, $key, $keyfile, $row, $ind, $ca, $type);

   $ca  = $main->{'keybrowser'}->selection_caname();
   $key = $main->{'keybrowser'}->selection_dn();

   if(not defined $key) {
      GUI::HELPERS::print_info(_("Please select a Key first"));
      return;
   }

   $keyname = HELPERS::enc_base64($key);

   $keyfile = $main->{'cadir'}."/keys/".$keyname.".pem";

   if(not -s $keyfile) {
      GUI::HELPERS::print_warning(_("Key file not found:".$keyfile));
      return;
   }

   $main->show_del_confirm($keyfile, 'key');

   return;
}

#
# now really delete the key
#
sub del_key {
   my ($self, $main, $file) = @_;

   unlink($file);

   my $cadir = $main->{'keybrowser'}->selection_cadir();

   $main->{'keybrowser'}->update($cadir."/keys",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   return;
}

#
# read keys in directory into list
#
sub read_keylist {
   my ($self, $main) = @_;

   my ($f, $modt, $tmp, $ca, $keydir, $keylist);

   $ca     = $main->{'CA'}->{'actca'};
   $keydir = $main->{'cadir'}."/keys";
   $keylist = [];

   $modt = (stat($keydir))[9];

   if(defined($self->{'lastread'}) &&
      $self->{'lastread'} >= $modt) { 
      return(0); 
   }

   opendir(DIR, $keydir) || do {
      GUI::HELPERS::print_warning(_("Can't open key directory"));
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $tmp = HELPERS::dec_base64($f);
      next if not defined($tmp);
      next if $tmp eq "";
      $tmp = _check_key($main, $keydir."/".$f.".pem", $tmp);
      push(@{$keylist}, $tmp);
   }
   @{$keylist} = sort(@{$keylist});
   closedir(DIR);

   $self->{'keylist'} = $keylist;

   $self->{'lastread'} = time();
   return(1);  # got new list
}

#
# get the information to export the key
#
sub get_export_key {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my($ca, $ind, $row, $t, $out, $cn, $email, $ret, $ext, $cadir);

   if(not defined($opts)) {
      $cn = $main->{'keybrowser'}->selection_cn();

      if(not defined $cn) {
         GUI::HELPERS::print_info(_("Please select a Key first"));
         return;
      }
      
      $ca    = $main->{'keybrowser'}->selection_caname();
      $cadir = $main->{'keybrowser'}->selection_cadir();
      $email = $main->{'keybrowser'}->selection_email();

      $opts->{'type'} = $main->{'keybrowser'}->selection_type();
      $opts->{'key'}  = $main->{'keybrowser'}->selection_dn();

      $opts->{'keyname'}  = HELPERS::enc_base64($opts->{'key'});
      $opts->{'keyfile'}  = $cadir."/keys/".$opts->{'keyname'}.".pem";
      $opts->{'certfile'} = $cadir."/certs/".$opts->{'keyname'}.".pem";
      
      # set some defaults
      $opts->{'nopass'}        = 0;
      $opts->{'include'}       = 0;
      $opts->{'format'}        = 'PEM';
      $opts->{'friendlyname'}  = '';

      if((defined($email)) && $email ne '' && $email ne ' ') {
         $opts->{'outfile'} = "$main->{'exportdir'}/$email-key.pem";
      }elsif((defined($cn)) && $cn ne '' && $cn ne ' ') {
         $opts->{'outfile'} = "$main->{'exportdir'}/$cn-key.pem";
      }else{
         $opts->{'outfile'} = "$main->{'exportdir'}/key.pem";
      }

      $main->show_export_dialog($opts, 'key');
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) {
      $main->show_export_dialog($opts, 'key');
      GUI::HELPERS::print_warning(_("Please give at least the output file"));
      return;
   }

   if(($opts->{'nopass'} || $opts->{'format'} eq 'DER') && 
      ((not defined($opts->{'passwd'})) || ($opts->{'passwd'} eq ''))) {
      $main->show_key_nopasswd_dialog($opts);
      return;
   }

   if(($opts->{'format'} eq 'PEM') || ($opts->{'format'} eq 'DER')) {
      unless(($opts->{'format'} eq 'PEM') && not $opts->{'nopass'}) {
         ($out, $ext) = $main->{'OpenSSL'}->convkey(
               'type'    => $opts->{'type'},
               'inform'  => 'PEM',
               'outform' => $opts->{'format'},
               'nopass'  => $opts->{'nopass'},
               'pass'    => $opts->{'passwd'},
               'keyfile' => $opts->{'keyfile'}
               );

         if(defined($out) && $out eq 1) {
            $t = _("Wrong password given\nDecrypting of the Key failed\nExport is not possible");
            GUI::HELPERS::print_warning($t, $ext);
            return;
         } elsif((not defined($out)) || (length($out) < 3)) {
            GUI::HELPERS::print_warning( 
               _("Converting failed, Export not possible"), $ext);
            return;
         }
      }

      if(($opts->{'format'} eq 'PEM') && not $opts->{'nopass'}) {
         open(IN, "<$opts->{'keyfile'}") || do {
            $t = sprintf(_("Can't open Key file: %s: %s"), 
                  $opts->{'keyfile'}, $!);
            GUI::HELPERS::print_warning($t);
            return;
         };
         $out .= $_ while(<IN>);
         close(IN);
      }
      if($opts->{'include'}) {
         open(IN, "<$opts->{'certfile'}") || do {
            $t = sprintf(_("Can't open Certificate file: %s: %s"), 
                  $opts->{'certfile'}, $!);
            GUI::HELPERS::print_warning($t);
            return;
         };
         $out .= "\n";
         $out .= $_ while(<IN>);
         close(IN);
      }

      open(OUT, ">$opts->{'outfile'}") || do {
            $t = sprintf(_("Can't open output file: %s: %s"), 
                  $opts->{'outfile'}, $!);
         GUI::HELPERS::print_warning($t);
         return;
      };

      print OUT $out;
      close(OUT);

      $main->{'exportdir'} = HELPERS::write_export_dir($main,
            $opts->{'outfile'});

      $t = sprintf(_("Key succesfully exported to %s"), 
            $opts->{'outfile'});
      GUI::HELPERS::print_info($t);
      return;

   } elsif ($opts->{'format'} eq 'P12') {
      $opts->{'certfile'} = 
         $main->{'cadir'}."/certs/".$opts->{'keyname'}.".pem";
      $opts->{'cafile'}   = 
         $main->{'cadir'}."/cacert.pem";

      if (-f $main->{'cadir'}."/cachain.pem") {
        $opts->{'cafile'} = $main->{'cadir'}."/cachain.pem";
      }

      if(not -s $opts->{'certfile'}) {
         $t = _("Certificate is necessary for export as PKCS#12");
         $t .= "\n";
         $t .= _("Export is not possible!");
         GUI::HELPERS::print_warning($t);
         return;
      }

      if((not defined($opts->{'p12passwd'})) &&
            (not $opts->{'nopass'})) {
         $opts->{'includeca'} = 1;
         $main->show_p12_export_dialog($opts, 'key');
         return;
      }

      unlink($opts->{'outfile'});
      ($ret, $ext) = $main->{'OpenSSL'}->genp12(
            type      => $opts->{'type'},
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

      if($ret eq 1) {
         $t = "Wrong password given\nDecrypting Key failed\nGenerating PKCS#12 failed";
         GUI::HELPERS::print_warning($t, $ext);
         return;
      } elsif($ret || (not -s $opts->{'outfile'})) {
         $t = _("Generating PKCS#12 failed");
         return;
      }

      $main->{'exportdir'} = HELPERS::write_export_dir($main, 
            $opts->{'outfile'});

      $t = sprintf(_("Certificate and Key successfully exported to %s"), 
            $opts->{'outfile'});
      GUI::HELPERS::print_info($t, $ext);
      return;

   } elsif (($opts->{'format'} eq "ZIP") || ($opts->{'format'} eq "TAR")) {
      $opts->{'certfile'} = 
         $main->{'cadir'}."/certs/".$opts->{'keyname'}.".pem";
      if(not -s $opts->{'certfile'}) {
         $t = sprintf(
               _("Certificate is necessary for export as %s file"), 
               $opts->{'format'});
         $t .= "\n";
         $t .= _("Export is not possible!");
         GUI::HELPERS::print_warning($t);
         return;
      }

      $opts->{'parsed'} = 
         $main->{'CERT'}->parse_cert($main, $opts->{'keyname'});

      my $tmpcert   = "$main->{'tmpdir'}/cert.pem";
      my $tmpkey    = "$main->{'tmpdir'}/key.pem";
      my $tmpcacert = "$main->{'tmpdir'}/cacert.pem";

      open(OUT, ">$tmpcert") || do {
         GUI::HELPERS::print_warning(_("Can't create temporary file"));
         return;
      };
      print OUT $opts->{'parsed'}->{'PEM'};
      close OUT;

      # store key in temporary location
      {
      open(IN, "<$opts->{'keyfile'}") || do {
         GUI::HELPERS::print_warning(_("Can't read Key file"));
         return;
      };
      my @key = <IN>;
      close IN;

      open(OUT, ">$tmpkey") || do {
         GUI::HELPERS::print_warning(_("Can't create temporary file"));
         return;
      };
      print OUT @key;
      close OUT;
      }

      # store cacert in temporary location
      {
      $opts->{'cafile'} = $main->{'cadir'}."/cacert.pem";
      open(IN, "<$opts->{'cafile'}") || do {
         GUI::HELPERS::print_warning(_("Can't read CA certificate"));
         return;
      };
      my @cacert = <IN>;
      close IN;

      open(OUT, ">$tmpcacert") || do {
         GUI::HELPERS::print_warning(_("Can't create temporary file"));
         return;
      };
      print OUT @cacert;
      close OUT;
      }

      unlink($opts->{'outfile'});
      if($opts->{'format'} eq 'ZIP') { 
         system($main->{'init'}->{'zipbin'}, '-j', $opts->{'outfile'},
               $tmpcacert, $tmpkey, $tmpcert); 
         my $ret = $? >> 8;
      } elsif ($opts->{'format'} eq 'TAR') {
         system($main->{'init'}->{'tarbin'}, 'cfv', $opts->{'outfile'},
               $tmpcacert, $tmpkey, $tmpcert); 
         my $ret = $? >> 8;
      }

      if(not -s $opts->{'outfile'} || $ret) {
         GUI::HELPERS::print_warning(
               sprintf(_("Generating %s file failed"), 
                  $opts->{'format'}));
      } else {
         $main->{'exportdir'} = HELPERS::write_export_dir($main, 
               $opts->{'outfile'});
         $t = sprintf( 
               _("Certificate and Key successfully exported to %s"), 
               $opts->{'outfile'});
         GUI::HELPERS::print_info($t);
      }
      unlink($tmpcacert);
      unlink($tmpcert);
      unlink($tmpkey);

      return;

   } else {
      $t = sprintf(_("Invalid format for export requested: %s"), 
            $opts->{'format'});
      GUI::HELPERS::print_warning($t);
      return;
   }

   GUI::HELPERS::print_warning(_("Something Failed ??"));

   return;
}

# check if its a dsa or rsa key
sub _check_key {
   my ($main, $file, $name) = @_;

   my ($t, $type);

   open(KEY, "<$file") || do {
      $t = sprintf(_("Can't open Key file: %s: %s"), 
            $file, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   while(<KEY>) {
      if(/RSA PRIVATE KEY/i) {
         $type = "RSA";
         last;
      } elsif(/DSA PRIVATE KEY/i) {
         $type = "DSA";
         last;
      } else {
         $type = "UNKNOWN";
      }
   }
   close(KEY);

   if(defined($type) && $type ne "") {
      $name .= "%".$type;
   }

   return($name);
}

sub key_change_passwd {
   my ($self, $main, $file, $oldpass, $newpass) = @_;
   my $opts = {};
   my ($t, $ret, $ext);

   my $inform  = "DER";
   my $outform = "PEM";

   my($type);

   # ckeck file format
   open(KEY, "<$file") || do {
      $t = sprintf(_("Can't open Key file:\n%s"),
            $file);
      GUI::HELPERS::print_warning($t);
      return(1);
   };
   while(<KEY>) {
      if(/BEGIN RSA PRIVATE KEY/) {
         $inform = "PEM";
         $type   = "RSA";
         last;
      } elsif(/BEGIN RSA PRIVATE KEY/){
         $inform = "PEM";
         $type   = "DSA";
         last;
      } else {
         $type   = "UNKNOWN";
      }
   }

   GUI::HELPERS::set_cursor($main, 1);

   ($ret, $ext) = $main->{'OpenSSL'}->convkey(
      'type'      => $type,
      'inform'    => $inform,
      'outform'   => $outform,
      'nopass'    => 0,
      'pass'      => $newpass,
      'oldpass'   => $oldpass,
      'keyfile'   => $file
   );

   GUI::HELPERS::set_cursor($main, 0);

   if($ret eq 1) {
      $t = _("Generating key failed");

      if($ext =~ /unable to load Private Key/) {
         $t .= _("The password for your old CA Key is wrong");
      }
      GUI::HELPERS::print_warning(($t), $ext);
      return($ret);
   }

   return($ret);
}

1
