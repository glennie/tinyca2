# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CALLBACK.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::CALLBACK;

use POSIX;

#
# fill given var-reference with text from entry
#
sub entry_to_var {
   my ($widget, $entry, $var, $box, $words) = @_;

   if(defined($words)) {
      $$var = $words->{$entry->get_text()};
   }else{
      $$var = $entry->get_text();
   }

   if(defined($box)) {
      $box->{'button_ok'}->set_sensitive(1);
      $box->{'button_apply'}->set_sensitive(1);
   }

   return;
}

#
# fill given var-reference with text from entry subjectAltName
# and set senitivity of togglebuttons
#
sub entry_to_var_san {
   my ($widget, $entry, $var, $box, $words, $radio1, $radio2, $radio3, $radio4) = @_;

   if(defined($words)) {
      if(my $tmp = $words->{$entry->get_text()}) {
         $$var = $tmp;
      } else {
         $$var = $entry->get_text();
      }
      #print STDERR "DEBUG: var: $$var\n";
      if($$var eq 'user') {
         #print STDERR "set sensitive(1)\n";
         $radio1->set_sensitive(1) if(defined($radio1));
         $radio2->set_sensitive(1) if(defined($radio2));
         $radio3->set_sensitive(1) if(defined($radio3));
         $radio4->set_sensitive(1) if(defined($radio4));
      }else{
         #print STDERR "DEBUG: set sensitive(0)\n";
         #print STDERR "DEBUG: r1 $radio1 r2 $radio2 r3 $radio3 r4 $radio4\n";
         $radio1->set_sensitive(0) if(defined($radio1));
         $radio2->set_sensitive(0) if(defined($radio2));
         $radio3->set_sensitive(0) if(defined($radio3));
         $radio4->set_sensitive(0) if(defined($radio4));
      }
   }else{
      $$var = $entry->get_text();
   }

   if(defined($box)) {
      $box->{'button_ok'}->set_sensitive(1);
      $box->{'button_apply'}->set_sensitive(1);
   }

   return;
}

#
# fill given var-reference with text from entry subjectAltName
# and set senitivity of togglebuttons
#
sub entry_to_var_key {
   my ($widget, $entry, $var, $box, $words, $radio1, $radio2, $radio3) = @_;

   if(defined($words)) {
      if(my $tmp = $words->{$entry->get_text()}) {
         $$var = $tmp;
      } else {
         $$var = $entry->get_text();
      }
      if(($$var ne '') && ($$var ne 'none')) {
         $radio1->set_sensitive(1) if(defined($radio1));
         $radio2->set_sensitive(1) if(defined($radio2));
         $radio3->set_sensitive(1) if(defined($radio3));
      }else{
         $radio1->set_sensitive(0) if(defined($radio1));
         $radio2->set_sensitive(0) if(defined($radio2));
         $radio3->set_sensitive(0) if(defined($radio3));
      }
   }else{
      $$var = $entry->get_text();
   }

   if(defined($box)) {
      $box->{'button_ok'}->set_sensitive(1);
      $box->{'button_apply'}->set_sensitive(1);
   }

   return;
}

#
# fill given var-reference with value from togglebutton
#
sub toggle_to_var {
   my ($button, $var, $value, $outfileref, $formatref, $fileentry, $pass1,
         $pass2) = @_;

   $$var = $value;

   if(defined($outfileref) && defined($formatref)) {
      if($$outfileref =~ s/\.(pem|der|txt|p12|zip|tar)$//i) {
         $$outfileref .= "." . lc $$formatref;
         # something seem broken, need tmp var
         my $tmp = $$outfileref;
         $fileentry->set_text($tmp);
      }
   }
   if(defined($pass1) && defined($pass2)) {
      if($$formatref eq "PEM") {
         $pass1->set_sensitive(1);
         $pass2->set_sensitive(1);
      } elsif ($$formatref eq "DER") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      } elsif ($$formatref eq "P12") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      } elsif ($$formatref eq "ZIP") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      } elsif ($$formatref eq "TAR") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      }
   }
   return;
}

#
# fill given var-reference with value from togglebutton
#
sub toggle_to_var_pref {
   my ($button, $var, $value, $box) = @_;

   $$var = $value;

   if(defined($box) && defined($box->{'nb'}->get_current_page())) {
      $box->{'button_ok'}->set_sensitive(1);
      $box->{'button_apply'}->set_sensitive(1);
   }

   return;
}

1

