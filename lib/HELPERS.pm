# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: HELPERS.pm,v 1.6 2006/06/28 21:50:41 sm Exp $
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
package HELPERS;

use POSIX;

my $version = "0.1";
my $true = 1;
my $false = undef;

# 
# generate filename from Subject-DN
# 
sub gen_name {
   my $opts = shift;

   my $name = '';

   foreach (qw(CN EMAIL OU O L ST C)) {
      if((not defined($opts->{$_})) || ($opts->{$_} eq '')) {
         $opts->{$_} = ".";
      }
      if($opts->{$_} ne '.' && not ref($opts->{$_})) {
         $name .= $opts->{$_};
      } elsif (ref($opts->{$_})) {
         if(defined($opts->{$_}->[0])) {
            $name .= $opts->{$_}->[0];
         } else {
            $name .= " ";
         }
      } else {
         $name .= " ";
      }
      $name .= ":" if($_ ne 'C');
   }

   return($name);
}

#
# generate temporary filename
#
sub mktmp { 
   my $base = shift;

   my @rand = ();
   my $ret  = '';

   do { 
      for(my $i = 0; $i < 8; $i++) { 
         push(@rand, int(rand 26)+65);
      }
      my $end = pack("C8", @rand);
      $ret = $base.$end;
   } while (-e $ret);

   return($ret);
}


#
# finished...
#
sub exit_clean {
   my ($ret) = @_;

   $ret = 0 unless(defined $ret);
   
   # hack to avoid busy cursor
   my $rootwin = Gtk2::Gdk->get_default_root_window();
   my $cursor  = Gtk2::Gdk::Cursor->new('left-ptr');

   $rootwin->set_cursor($cursor);
   
   Gtk2->main_quit();
   exit($ret);
}

#
# split Subject DN and return hash
#
sub parse_dn {
   my $dn = shift;

   my (@dn, $k, $v, $tmp);

   $tmp = {};

   $dn =~ s/,/\//g;

   @dn = split(/\//, $dn);
   foreach(@dn) {
      s/^\s+//;
      s/\s+$//;
      ($k, $v) = split(/=/);
      next if(not defined($k));
      if($k =~ /ou/i) {
         $tmp->{'OU'} or  $tmp->{'OU'} = [];
         push(@{$tmp->{'OU'}}, $v);
      } else {
         if($k =~ /emailaddress/i) {
            $tmp->{'EMAIL'} = $v;
         } else {
            $tmp->{uc($k)} = $v;
         }
      }
   }
      
   return($tmp);
}

#
# parse (requested) X509 extensions and return hash
#
sub parse_extensions {
   my ($lines, $mode) = @_;

   my ($sep, $i, $k, $v, $tmp);

   $sep = $mode eq "req"?"Requested extensions:":"X509v3 extensions:";

   $tmp = {};

   # skip everything before the extensions
   for($i = 0; defined($lines->[$i]) && $lines->[$i] !~ /^[\s\t]*$sep$/i; $i++) {
      return(undef) if not defined($lines->[$i]);
   }
   $i++;

   while($i < @{$lines}) {
      if(($lines->[$i] =~ /^[\s\t]*[^:]+:\s*$/) ||
            ($lines->[$i] =~ /^[\s\t]*[^:]+:\s+.+$/)) {
         if($lines->[$i] =~ /^[\s\t]*Signature Algorithm/i) {
            $i++;
            next;
         }
         $k = $lines->[$i];
         $k =~ s/[\s\t:]*$//g;
         $k =~ s/^[\s\t]*//g;
         $tmp->{$k} = [];
         $i++;
         while(($lines->[$i] !~ /^[\s\t].+:\s*$/) &&
               ($lines->[$i] !~ /^[\s\t]*[^:]+:\s+.+$/) &&
               ($lines->[$i] !~ /^[\s\t]*Signature Algorithm/i) &&
               ($i < @{$lines})) {
            $v = $lines->[$i];
            $v =~ s/^[\s]+//g;
            $v =~ s/[\s]+$//g;
            $i++;
            next if $v =~ /^$/;
            next if $v =~ /Signature Algorithm:/;
            my @vs = split(/,/, $v);
            foreach(@vs) {
               $_ =~ s/^\s//;
               $_ =~ s/\s$//;
               push(@{$tmp->{$k}}, $_);
            }
         }
      } else {
         $i++;
      }
   }

   return($tmp);
}

#
# get last used export directory
#
sub get_export_dir {
   my $main = shift;

   open(EXPIN, "<$main->{'cadir'}/.exportdir") || return(undef);
   my $dir = <EXPIN>;
   chomp($dir);

   return($dir);
}

#
# write last used export directory
#
sub write_export_dir {
   my ($main, $dir) = @_;

   $dir =~ s:/[^/]+$::;

   open(EXPOUT, ">$main->{'cadir'}/.exportdir") || do {
      my $t = sprintf(_("Can't write exportdir: %s, %s"), 
               "$main->{'cadir'}/.exportdir", $!);
      GUI::HELPERS::print_warning($t);
      return;
   };
   print EXPOUT "$dir\n";

   close(EXPOUT);

   return($dir);
}

#
# generate contents for subjectAltName
#
sub gen_subjectaltname_contents($@)
{
my $type = shift || '';
my @input = map { split/,\s*|\s+/, $_ } @_; # split on ',' and ' '
my %output = ();        # uniq on the fly

  if ($type) {	# type given => use that one for all
    foreach my $elem (@input) {
      $output{$type.$elem} = 1;
    }
  }
  else {	# no type => use heuristigcs to guess type per element
    foreach my $elem (@input) {
      if ($elem =~ s/^(ip:|dns:)(.*)/$2/i) {
        $type = uc($1);
      } elsif ($elem =~ s/^(email:)(.*)/$2/i) {
        $type = lc($1);
      } else {
        if ($elem =~ /^\d+\.\d+\.\d+\.\d+$/) {	# it's an IP address
          $type = 'IP:';
        }
        elsif ($elem =~ /^.+\@.+\.\w+$/) {	# it's a mail address
          $type = 'email:';
        }
        else {
          $type = 'DNS:'			# otherwise it's a DNS name
        }
      }
      $output{$type.$elem} = 1;
    }  
  }
  return(wantarray ? keys(%output) : join(', ', keys(%output)));
}

sub enc_base64 {
	my $data = shift;
	my $ret = MIME::Base64::encode($data, '');
	$ret =~ tr/\/+/-_/;
    return $ret;
}

sub dec_base64 {
	my $data = shift;
	$data =~ tr/-_/\/+/;
	return MIME::Base64::decode($data);	
}


1

__END__

=head1 NAME

HELPERS - helper functions for TinyCA, doing small jobs not related to the GUI

=head1 SYNOPSIS

   use HELPERS;

   $name    = HELPERS::gen_name($opts);
   $tmpnam  = HELPERS::mktmp($base);
   $dnhash  = HELPERS::parse_dn($dnstring);
   $exthash = HELPERS::parse_extensions($mode, $lines);
   $subjaltname = HELPERS::gen_subjectaltname_contents($type, @list);
   
   exit_clean($retcode);

=head1 DESCRIPTION

HELPERS.pm is just a library, containing some useful functions used by other
TinyCA modules.

=head1 FUNCTIONS

=head2 HELPERS::gen_name($opts)

=over 1

returns a string with the TinyCA filename for a certificate, request or key.
The filename is generated from the following parts of the Subject DN from the
related request or certificate if present:

   CN EMAIL OU O L ST C

These parts need to be elements in the given options hash.

=back

=head2 HELPERS::mktmp($base)

=over 1

returns a string, containing a uniqe filename starting with $base, which is
not existing yet.

$base needs to be an absolute path to allow HELPERS::mktmp() reliable check
that the filename is really uniqe.

=back

=head2 HELPERS::parse_dn($dnstring)

=over 1

returns the reference to a hash containing all elements of the Subject DN,
given in $dnstring.

The element OU is included as an array refernce in the hash, with an array
containing all values of OU.

=back

=head2 HELPERS::parse_extensions($mode, $lines)

=over 1

returns the reference to a hash containing all X509 extensions of the given
request or certificate.

The request or certificate is given in textform as an array reference
with the array containing one line per element.

$mode contains one of the strings "req" or "cert" depending on the type of the
data.

=back

=head2 HELPERS::exit_clean($retcode)

=over 1

does nothing yet, than closing the Gtk application returning the exitcode
given in $retcode.

=back

=head2 $main->HELPERS::get_export_dir()

=over 1

Get last used export directory.

=back

=head2 $main->HELPERS::write_export-dir($dir)

=over 1

Store last used export directory

=back

=head2 HELPERS::gen_subjectaltname_contents($type, @list)

=over 1

Generate a string suitable for the use as subjhectAltname contets for OpenSSL.

If $Type is not empty create the contents of that type only,
otherwise use either the type prefix of the list elements or
the following heuristics to find the type for the appropriate elements:

If the element looks like an IP address in dotted quad notation set
then treat it as one.
If the element contains a '@' followed by a '.' and a sequence of letters
then treat the element as an email address.
In all other cases treat it as a DNS name.

=back

=cut
