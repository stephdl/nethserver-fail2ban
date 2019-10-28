#
# Copyright (C) 2019 Nethesis S.r.l.
# http://www.nethesis.it - nethserver@nethesis.it
#
# This script is part of NethServer.
#
# NethServer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License,
# or any later version.
#
# NethServer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NethServer.  If not, see COPYING.
#
package NethServer::Fail2Ban;

use strict;
use esmith::ConfigDB;

=head1 NAME
NethServer::Fail2ban -- utility functions for fail2ban
=cut

=head1 DESCRIPTION
TODO
=cut

=head1 USAGE
Usage example:
  use NethServer::Fail2ban;
  ...
=cut

=head1 FUNCTIONS
=head2 listJails
Return the list of jails
=cut

sub listAllJails {
    my @jails;
    push(@jails, listApacheErrorJails());
    push(@jails, listApacheAccessJails());
    push(@jails, listSSHJails());
    push(@jails, listAsteriskJails());
    push(@jails, listDovecotJails());
    push(@jails, listHttpdAdminJails());
    push(@jails, listEjabberAuthJails());
    # ... other jails

    return @jails;
}

sub listEjabberAuthJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $ejabberd = $db->get_prop('ejabberd', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'EjabberAuth_status') || 'true';

    if (( -f '/var/log/ejabberd/ejabberd.log') &&  
      ($status eq 'true') && 
      ($ejabberd eq 'enabled')) {
        push(@jails, 'ejabberd-auth');
    }
    return @jails;
}

sub listHttpdAdminJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd_admin = $db->get_prop('httpd-admin', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'HttpdAdmin_status') || 'true';

    if (( -f '/var/log/httpd-admin/access_log') &&
      ($status eq 'true') && 
      ($httpd_admin eq 'enabled')) {
        push(@jails, 'httpd-admin');
    }
    return @jails;
}

sub listDovecotJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $dovecot = $db->get_prop('dovecot', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'Dovecot_status') || 'true';

    if ( -f '/var/log/imap') {
        foreach (qw( dovecot dovecot-nethserver )) {
            if (($status eq 'true') && ($dovecot eq 'enabled')) {
                push(@jails, $_);
            }
        }
    }
    return @jails;
}

sub listAsteriskJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $asterisk = $db->get_prop('asterisk', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'AsteriskAuth_status') || 'true';

    if ( -f '/var/log/asterisk/full') {
        foreach (qw( asterisk asterisk_nethserver )) {
            if (($status eq 'true') && ($asterisk eq 'enabled')){
                push(@jails, $_);
            }
        }
    }
    return @jails;
}

sub listSSHJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $sshd = $db->get_prop('sshd', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'Sshd_status') || 'true';

    if (( -f '/var/log/secure') &&
      ($status eq 'true') && 
      ($sshd eq 'enabled')) {
        push(@jails, 'sshd');
    }
    return @jails;
}

sub listApacheErrorJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd = $db->get_prop('httpd', 'status') || 'enabled';
    my $apache = $db->get_prop('fail2ban', 'ApacheAuth_status') || 'true';
    return ("\n#apache not used on this server\n") if ($httpd eq 'disabled' || $apache eq 'false');

    if ( -f '/var/log/httpd/error_log') {
        foreach (qw(auth noscript overflows nohome botsearch modsecurity shellshock scan )) {
            my $status = $db->get_prop('fail2ban', 'Apache'.$_.'_status') || 'true';
            if ($status eq 'true') {
                push(@jails, 'apache-'.$_);
            }
        }
    }
    return @jails;
}

sub listApacheAccessJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd = $db->get_prop('httpd', 'status') || 'enabled';
    my $apache = $db->get_prop('fail2ban', 'ApacheAuth_status') || 'true';
    return ("\n#apache not used on this server\n") if ($httpd eq 'disabled' || $apache eq 'false');

    if (-f '/var/log/httpd/access_log') {
        foreach(qw(fakegooglebot badbots)) {
            my $status = $db->get_prop('fail2ban', 'Apache'.$_.'_status') || 'true';
            if ($status eq 'true') {
                push(@jails, 'apache-'.$_);
            }
        }
        my $phpmyadmin = $db->get_prop('fail2ban', 'ApachePhpMyAdmin_status') || 'true';
        if ($phpmyadmin eq 'true') {
            push(@jails, 'phpmyadmin');
        }

    }
    return @jails;
}


1;