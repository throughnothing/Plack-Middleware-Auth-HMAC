use HTTP::Request::Common;
use Test::Most;

use t::lib::Helper qw( test_app hmac_b64 gen_nonce secret serialize_req );

subtest 'GET test' => sub {
	my $ta = test_app(
		get_secret => sub { return secret if shift == 1 },
	);
	my $nonce = gen_nonce;
	my $req = GET 'https://www.test.com/test?test=432';
	my $sig = hmac_b64 'SHA1', secret , serialize_req( $req, $nonce );
	$req->header(authorization => "HMAC 1:$nonce:$sig");
	ok $ta->request($req)->is_success, 'Everything works™';

	# Change the id in the auth header to something invalid
	$req->header(authorization => "HMAC 2:$nonce:$sig");
	like $ta->request($req)->content => qr/Invalid ID/, 'get_secret check works';
};

done_testing;
