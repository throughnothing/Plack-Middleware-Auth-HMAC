package t::lib::Helper;
use Crypt::Mac::HMAC qw(hmac_b64);
use Exporter 'import';
use Plack::Test;

use Plack::Middleware::Auth::HMAC;

@EXPORT_OK = qw(app hmac_b64 gen_nonce secret serialize_req test_app);

sub secret { 'asdf' }
sub test_app { Plack::Test->create(app(@_)) }
sub gen_nonce { int rand 999 }

sub app {
	my (%args) = @_;
	# Setup a default app, if none given
	my $app = $args{app} || sub { [200, [], ["Yay!"]] };
	# Add Auth::HMAC Middleware to the app
	$app = Plack::Middleware::Auth::HMAC->wrap(
		$app,
		hash          => $args{hash}          || 'SHA1',
		check_nonce   => $args{check_nonce}   || sub { 1 },
		get_secret    => $args{get_secret}    || \&secret,
		serialize_req => $args{serialize_req} || \&serialize_req,
	);
}

sub serialize_req {
	my ($req, $nonce) = @_;
	return $nonce . $req->uri . $req->content;
}

1;
