# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: HELPERS.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::HELPERS;

use POSIX;

#
#  Error message box, kills application
#
sub print_error {
   my ($t, $ext) = @_;
   
   my ($box, $button, $dbutton, $expander, $text, $scrolled, $buffer);

   $button = Gtk2::Button->new_from_stock('gtk-ok');
   $button->signal_connect('clicked', sub { HELPERS::exit_clean(1) });
   $button->can_default(1);

   $box = Gtk2::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'error', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $buffer = Gtk2::TextBuffer->new();
      $buffer->set_text($ext);

      $text = Gtk2::TextView->new_with_buffer($buffer);
      $text->set_editable(0);
      $text->set_wrap_mode('word');

      $scrolled = Gtk2::ScrolledWindow->new(undef, undef);
      $scrolled->set_policy('never', 'automatic');
      $scrolled->set_shadow_type('etched-in');
      $scrolled->add($text);

      $expander = Gtk2::Expander->new(_("Command Details"));
      $expander->add($scrolled);
      $box->vbox->add($expander);
   }

   $box->add_action_widget($button, 0);

   $box->show_all();
}

#
#  Warning message box
#
sub print_warning {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $expander, $text, $scrolled, $buffer);

   $button = Gtk2::Button->new_from_stock('gtk-ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   $box = Gtk2::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'warning', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $buffer = Gtk2::TextBuffer->new();
      $buffer->set_text($ext);

      $text = Gtk2::TextView->new_with_buffer($buffer);
      $text->set_editable(0);
      $text->set_wrap_mode('word');

      $scrolled = Gtk2::ScrolledWindow->new(undef, undef);
      $scrolled->set_policy('never', 'automatic');
      $scrolled->set_shadow_type('etched-in');
      $scrolled->add($text);

      $expander = Gtk2::Expander->new(_("Command Details"));
      $expander->add($scrolled);
      $box->vbox->add($expander);
   }
   $box->add_action_widget($button, 0);

   $box->show_all();

   return;
}

#
#  Info message box
#
sub print_info {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $buffer, $text, $scrolled, $expander);

   $button = Gtk2::Button->new_from_stock('gtk-ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   $box = Gtk2::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'info', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $buffer = Gtk2::TextBuffer->new();
      $buffer->set_text($ext);

      $text = Gtk2::TextView->new_with_buffer($buffer);
      $text->set_editable(0);
      $text->set_wrap_mode('word');

      $scrolled = Gtk2::ScrolledWindow->new(undef, undef);
      $scrolled->set_policy('never', 'automatic');
      $scrolled->set_shadow_type('etched-in');
      $scrolled->add($text);

      $expander = Gtk2::Expander->new(_("Command Details"));
      $expander->add($scrolled);
      $box->vbox->add($expander);
   }
   $box->add_action_widget($button, 0);

   $box->show_all();

   return;
}

#
# create standard dialog box
#
sub dialog_box {
   my ($title, $text, $button1, $button2) = @_;

   my $box = Gtk2::Dialog->new($title, undef, ["destroy-with-parent"]);

   $box->add_action_widget($button1, 0);

   if(defined($button2)) {
      $box->add_action_widget($button2, 0);
      $box->action_area->set_layout('spread');
   }

   if(defined($text)) {
      my $label = create_label($text, 'center', 0, 1);
      $box->vbox->pack_start($label, 0, 0, 0);
   }

   $box->signal_connect(response => sub { $box->destroy });

   return($box);
}

#
# create standard label 
#
sub create_label {
   my ($text, $mode, $wrap, $bold) = @_;

   $text = "<b>$text</b>" if($bold);

   my $label = Gtk2::Label->new($text);

   $label->set_justify($mode); 
   if($mode eq 'center') { 
      $label->set_alignment(0.5, 0.5); 
   }elsif($mode eq 'left') { 
      $label->set_alignment(0, 0); 
   }elsif($mode eq 'right') { 
      $label->set_alignment(1, 1); 
   } 
   
   $label->set_line_wrap($wrap); 
   
   $label->set_markup($text) if($bold);
   
   return($label);
}

#
# write two labels to table
#
sub label_to_table {
   my ($key, $val, $table, $row, $mode, $wrap, $bold) = @_;

   my ($label, $entry);

   $label = create_label($key, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $label = create_label($val, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 1, 2, $row, $row+1);

   $row++;
   $table->resize($row, 2);

   return($row);
}

#
# write label and entry to table
#
sub entry_to_table {
   my ($text, $var, $table, $row, $visibility, $box) = @_;

   my ($label, $entry);

   $label = create_label($text, 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $entry = Gtk2::Entry->new();
   $entry->set_text($$var) if(defined($$var));

   $table->attach_defaults($entry, 1, 2, $row, $row+1);
   $entry->signal_connect('changed' =>
         sub {GUI::CALLBACK::entry_to_var($entry, $entry, $var, $box)} );
   $entry->set_visibility($visibility);

   return($entry);
}

#
# sort the table by the clicked column
#
sub sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}

sub create_activity_bar {
   my ($t) = @_;

   my($box, $bar);

   $box = Gtk2::MessageDialog->new(
      undef, [qw/destroy-with-parent modal/], 'info', 'none', $t);

   $bar = Gtk2::ProgressBar->new();
   $bar->pulse();
   $bar->set_pulse_step(0.1);

   $box->vbox->add($bar);

   $box->show_all();

   return($box, $bar);
}

#
# set curser busy
#
sub set_cursor {
   my $main = shift;
   my $busy = shift;

   if($busy) {
      $main->{'rootwin'}->set_cursor($main->{'busycursor'});
   } else {
      $main->{'rootwin'}->set_cursor($main->{'cursor'});
   }
   while(Gtk2->events_pending) {
      Gtk2->main_iteration;
   }
}

#
# call file chooser
#
sub browse_file {
   my($title, $entry, $mode) = @_;

   my($file_chooser, $filename, $filter);

   $file_chooser = Gtk2::FileChooserDialog->new ($title, undef, $mode, 
         'gtk-cancel' => 'cancel', 
         'gtk-ok' => 'ok'); 

   $file_chooser->add_shortcut_folder ('/tmp');

   if($mode eq 'open') {
      $filter = Gtk2::FileFilter->new();
      $filter->set_name(_("Request Files (*.pem, *.der, *.req)"));
      $filter->add_pattern("*.pem");
      $filter->add_pattern("*.der");
      $filter->add_pattern("*.req");
      $file_chooser->add_filter($filter);

      $filter = Gtk2::FileFilter->new();
      $filter->set_name(_("All Files (*.*)"));
      $filter->add_pattern("*");
      $file_chooser->add_filter($filter);
   }

   if ('ok' eq $file_chooser->run) {
      $filename = $file_chooser->get_filename();
      $entry->set_text($filename);
   }

   $file_chooser->destroy();
}

#
# set text in statusbar
#
sub set_status {
   my ($main, $t) = @_;

   $main->{'bar'}->pop($main->{'lastid'}) if(defined($main->{'lastid'}));
   $main->{'lastid'} = $main->{'bar'}->get_context_id('gargs');
   $main->{'bar'}->push($main->{'lastid'}, $t);
}

1

__END__

=head1 NAME

GUI::HELPERS - helper functions for TinyCA, doing small jobs related to the
GUI

=head1 SYNOPSIS

 use GUI::HELPERS; 

 GUI::HELPERS::print_info($text, $ext);
 GUI::HELPERS::print_warning($text, $ext);
 GUI::HELPERS::print_error($text, $ext);
 GUI::HELPERS::sort_clist($clist, $col);
 GUI::HELPERS::set_cursor($main, $busy);
 GUI::HELPERS::browse_file($main, $entry, $mode);
 GUI::HELPERS::set_status($main, $text);

 $box   = GUI::HELPERS::dialog_box(
       $title, $text, $button1, $button2);
 $label = GUI::HELPERS::create_label(
       $text, $mode, $wrap, $bold);
 $row   = GUI::HELPERS::label_to_table(
       $key, $val, $table, $row, $mode, $wrap, $bold);
 $entry = GUI::HELPERS::entry_to_table(
       $text, $var, $table, $row, $visibility, $box);

=head1 DESCRIPTION

GUI::HELPERS.pm is a library, containing some useful functions used by other
TinyCA2 modules. All functions are related to the GUI.

=head2 GUI::HELPERS::print_info($text, $ext);

=over 1

creates an Gtk2::MessageDialog of the type info. The string given in $text is
shown as message, the (multiline) string $ext is available through the
"Details" Button.

=back

=head2 GUI::HELPERS::print_warning($text, $ext);

=over 1

is identically with GUI::HELPERS::print_warning(), only the
Gtk2::MessageDialog is of type warning.

=back

=head2 GUI::HELPERS::print_error($text, $ext);

=over 1

is identically with GUI::HELPERS::print_info(), only the Gtk2::MessageDialogog
is of type error and the program will shut down after closing the message.

=back

=head2 GUI::HELPERS::sort_clist($clist, $col);

=over 1

sorts the clist with the values from the given column $col.
   
=back

=head2 GUI::HELPERS::dialog_box($title, $text, $button1, $button2);

=over 1

returns the reference to a new window of type Gtk2::Dialog. $title and
$button1 must be given.  $text and $button2 are optional arguments and can be
undef.

=back

=head2 GUI::HELPERS::create_label($text, $mode, $wrap, $bold);

=over 1

returns the reference to a new Gtk2::Label. $mode can be "center", "left" or
"right". $wrap and $bold are boolean values.

=back

=head2 GUI::HELPERS::label_to_table($key, $val, $table, $row, $mode, $wrap, $bold);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of string $k, the second the
content of string $v. $mode, $wrap, $bold are the arguments for
GUI::HELPERS::create_label(), mentioned above. 
The function returns the number of the next free row in the table.

=back

=head2 GUI::HELPERS::entry_to_table($text, $var, $table, $row, $visibility, $box);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of the string $text, the
second one will contain a textentry Gtk2::Entry, associated with the variable
$var. $visibility controls, if the entered text will be displayed or not
(passwords).
The function returns the reference to the new created entry.

=back

=head2 GUI::HELPERS::set_cursor($main, $busy);

=over 1

sets the actual cursor to busy or back to normal. The value of $busy is
boolean.
This functions returns nothing;

=back

=head2 GUI::HELPERS::browse_file($main, $entry, $mode);

=over 1

opens a FileChooser dialog to select files or directories. $entry is a
reference to the variable, where the selected path shall be stored. If $mode
is set to "open", then only files with appropriate suffixes are displyed.

=back

=head2 GUI::HELPERS::set_status($main, $text);

=over 1

sets the text in $text to the statusbar at the bottom of the window.

=back

=cut
