<?php
include_once 'vendor/autoload.php';

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\HttpClient\HttpClient;


function ip_location($ip)
{
    $client = HttpClient::create();
    $response = $client->request('GET', 'http://ip-api.com/json/' . $ip);
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $result = $response->getContent();
        $result = json_decode($result, false);
        $result = $result->country;
        return json_encode($result);
    } else
        return "not valid ip";
}


function dig_domain($domain, $nameserver, $nameserver2 = null)
{

    $ip2 = gethostbyname($nameserver2);
    $ip = gethostbyname($nameserver);
    $dns = new Net_DNS2_Resolver(array('nameservers' => array($ip, $ip2)));

    try {
        $soa = $dns->query($domain, 'SOA');
        $a = $dns->query($domain, 'A');
        $ns = $dns->query($domain, 'NS');

        $soa = $soa->answer[0]->mname;
        $a = $a->answer[0]->address;
        $ns = array($ns->answer[0]->nsdname, $ns->answer[1]->nsdname, $ns->answer[2]->nsdname);

        $ns_final = array();
        foreach ($ns as $nameserver) {
            if ($nameserver)
                array_push($ns_final, $nameserver);
        }

        $result = array("SOA" => $soa, "A" => $a, "NS" => $ns_final);

        return json_encode($result);

    } catch (Net_DNS2_Exception $e) {

        return "::query() failed: " . $e->getMessage() . "\n";
    }

}


function dom_whois($domain)
{
    $whois = new Whois();
    $result = $whois->lookup($domain, false);

//    $whois_server = $result["regyinfo"]["servers"][0]["server"];
//    $nserver = $result["regrinfo"]["domain"]["nserver"];
//    $whois_info = array($result["rawdata"][4], $result["rawdata"][6], $result["rawdata"][14], $result["rawdata"][18], $result["rawdata"][28]);
//    $result = array("DOMAIN INFO" => $whois_info, "WHOIS SERVER" => $whois_server, "NSERVER" => $nserver);
    return json_encode($result);

}


class IP_COMMAND extends Command
{
    protected static $defaultName = 'ip:location';

    protected function configure()
    {
        $this->setDescription('IP Location');
        $this->addArgument('ip', InputArgument::REQUIRED, 'IP Field');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $location = ip_location($input->getArgument("ip"));

        $output->writeln("The IP Country : " . $location);
        return 0;
    }
}


class HOSTED_COMMAND extends Command
{
    protected static $defaultName = 'hosted:domain';

    protected function configure()
    {
        $this->setDescription('is domain hosted?');
        $this->addArgument('domain', InputArgument::REQUIRED, 'domain Field');
        $this->addArgument('nameserver', InputArgument::REQUIRED, 'nameserver Field');
        $this->addArgument('nameserver2', InputArgument::OPTIONAL, 'nameserver2 Field');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $hosted = dig_domain($input->getArgument("domain"), $input->getArgument("nameserver"), $input->getArgument("nameserver2"));

        $output->writeln($hosted);
        return 0;
    }
}


class WHOIS_COMMAND extends Command
{
    protected static $defaultName = 'whois:domain';

    protected function configure()
    {
        $this->setDescription('whois domain');
        $this->addArgument('domain', InputArgument::REQUIRED, 'domain Field');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $whois_domain = dom_whois($input->getArgument("domain"));

        $output->writeln($whois_domain);
        return 0;
    }
}


///////////////////////////////////////////////////////////////////////// the output:


if (php_sapi_name() == "cli") {
    $application = new Application();
    $application->add(new IP_COMMAND());
    $application->add(new HOSTED_COMMAND());
    $application->add(new WHOIS_COMMAND());
    $application->run();


} else {
    $app = new Silex\Application();

    $app->get('/', function () {
        return "<h1>please enter the domain in the url:  /whois/{domain}</h1>";
    });
    $app->get('/iplocation/{ip}', function ($ip) {
        $location = ip_location($ip);
        return "<h2>" . $location . "</h2>";
    });

    $app->get('/whois/{domain}', function ($domain) {
        return dom_whois($domain);
    });
    $app->get('/dig/{domain}/{nameserver}', function ($domain, $nameserver) {
        $hosted = dig_domain($domain, $nameserver);
        return $hosted;
    });

    $app->get('/dig/{domain}/{nameserver}/{nameserver2}', function ($domain, $nameserver,$nameserver2) {
        $hosted = dig_domain($domain, $nameserver, $nameserver2);
        return $hosted;
    });
    $app->run();


}