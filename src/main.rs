use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ec2::{Client as EC2Client, Region};
use clokwerk::{AsyncScheduler, TimeUnits};
use paris::{error, info, success, warn};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use slack_hook::{PayloadBuilder, Slack};
use std::env;
use std::error::Error;
use std::time::Duration;
use tokio::task;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

#[tokio::main]
async fn main() {
    let mut scheduler = AsyncScheduler::new();
    scheduler.every(2.minutes()).run(|| async {
        handle().await;
    });

    loop {
        scheduler.run_pending().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle() {
    let regions = vec![
        "us-east-2",
        "us-west-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "eu-central-1",
        "ap-southeast-1",
        "ap-southeast-2",
    ];

    for region in regions {
        let region = region.to_string();

        let count_elastic_ip = count_elastic_ip(&region).await;
        if count_elastic_ip > 0 {
            warn!("{} Elastic IP(s) found in {}", count_elastic_ip, region);
            continue;
        }

        let (public_ip, allocation_id) = allocate_elastic_ip(&region).await;
        let shodan_api_key = env::var("SHODAN_API_KEY").expect("Error: SHODAN_API_KEY not found");

        let hostname_shodan = shodan_lookup(&public_ip, shodan_api_key).await.unwrap();
        let hostnames_reverse = reverse_lookup(public_ip.clone()).await.unwrap();
        let mut hostnames = hostname_shodan;
        hostnames.append(&mut hostnames_reverse.clone());

        let matches = lookup(hostnames, public_ip.clone()).await.unwrap();

        if matches.len() == 0 {
            info!("No dangling records found for: {}", public_ip);
            release_elastic_ip(&region, &allocation_id).await;
        }

        for hostname in matches {
            success!(
                "Dangling record found in {} on {} for {} (allocation ID: {})",
                region,
                hostname,
                public_ip,
                allocation_id
            );
            notify(
                format!(
                    "Dangling record found in {} on {} for {} (allocation ID: {})",
                    region,
                    hostname,
                    public_ip,
                    allocation_id
                ),
                ":fishing_pole_and_fish:",
            );
        }
    }
}

fn notify(text: String, icon_emoji: &str) {
    let slack_webhook_url =
        env::var("SLACK_WEBHOOK_URL").expect("Error: SLACK_WEBHOOK_URL not found");
    let slack = Slack::new(slack_webhook_url.as_str()).unwrap();
    let p = PayloadBuilder::new()
        .text(text)
        .channel("#eips")
        .username("EIP Bot")
        .icon_emoji(icon_emoji)
        .build()
        .unwrap();
    let res = slack.send(&p);
    if res.is_err() {
        error!("Error sending Slack message: {}", res.err().unwrap());
    }
}

async fn count_elastic_ip(region: &String) -> u8 {
    let provider = Some(Region::new(region.clone()));
    let region_provider = RegionProviderChain::first_try(provider).or_default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = EC2Client::new(&config);
    let describe_response = client.describe_addresses().send().await.unwrap();
    let addresses = describe_response.addresses.unwrap();
    let count = addresses.len() as u8;
    count
}

async fn allocate_elastic_ip(region: &String) -> (String, String) {
    let provider = Some(Region::new(region.clone()));
    let region_provider = RegionProviderChain::first_try(provider).or_default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = EC2Client::new(&config);
    let allocate_response = client.allocate_address().send().await.unwrap();
    let public_ip = allocate_response.public_ip.unwrap();
    let allocation_id = allocate_response.allocation_id.unwrap();
    info!(
        "Elastic IP address allocated in {} for: {}",
        region, public_ip
    );
    (public_ip, allocation_id)
}

async fn release_elastic_ip(region: &String, allocation_id: &str) {
    let provider = Some(Region::new(region.clone()));
    let region_provider = RegionProviderChain::first_try(provider).or_default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = EC2Client::new(&config);

    let release_response = client
        .release_address()
        .allocation_id(allocation_id)
        .send()
        .await;
    if release_response.is_err() {
        error!(
            "Error releasing Elastic IP address: {}",
            release_response.err().unwrap()
        );
    } else {
        info!(
            "Elastic IP address released in {} for allocation ID: {}",
            region, allocation_id
        );
    }
}

async fn shodan_lookup(public_ip: &str, api_key: String) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("https://api.shodan.io/shodan/host/{}", public_ip);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;
    let response = client
        .get(&url)
        .query(&[("key", api_key)])
        .send()
        .await?
        .text()
        .await?;

    let reverse_dns: serde_json::Value = serde_json::from_str(&response).unwrap_or_else(|_| {
        error!("Error parsing Shodan response for: {}", public_ip);
        serde_json::Value::Null
    });

    if reverse_dns.is_null() {
        return Ok(vec![]);
    }

    let hostnames = reverse_dns["hostnames"].as_array();

    return if hostnames.is_none() {
        info!("No reverse DNS hostnames found for: {}", public_ip);
        Ok(vec![])
    } else {
        let hostnames = hostnames.unwrap();
        let results = hostnames
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        info!(
            "Reverse DNS hostnames found for: {} on {}",
            public_ip,
            results.join(", ")
        );
        Ok(results)
    };
}

async fn reverse_lookup(public_ip: String) -> Result<Vec<String>, Box<dyn Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    let results = task::spawn_blocking(move || {
        let public_ip = public_ip.clone();
        let response = resolver.reverse_lookup(public_ip.parse().unwrap());
        return if response.is_err() {
            error!(
                "Error performing reverse lookup: {}",
                response.err().unwrap()
            );
            vec![]
        } else {
            info!("Reverse lookup successful for {}", public_ip);
            let hostnames = response
                .unwrap()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>();
            hostnames
        };
    })
    .await
    .unwrap();

    return Ok(results);
}

async fn lookup(hostnames: Vec<String>, public_ip: String) -> Result<Vec<String>, Box<dyn Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    let results = task::spawn_blocking(move || {
        let mut matches: Vec<String> = Vec::new();
        let blacklist = Regex::new(r"amazonaws|cloudfront").unwrap();

        for hostname in hostnames {
            if blacklist.is_match(&hostname) {
                continue;
            }
            let response = resolver.lookup_ip(hostname.clone());
            if response.is_err() {
                error!("Error performing lookup: {}", response.err().unwrap());
                continue;
            } else {
                info!("Lookup successful for {}", hostname);
                let ips = response
                    .unwrap()
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>();
                if ips.contains(&public_ip) {
                    info!("Lookup match for {}", hostname);
                    matches.push(hostname);
                }
            }
        }
        matches
    })
    .await;

    if results.is_err() {
        error!("Error performing lookup: {}", results.err().unwrap());
        Ok(Vec::from([] as [String; 0]))
    } else {
        Ok(results.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shodan_lookup() {
        let public_ip = "8.8.8.8";
        let api_key = env::var("SHODAN_API_KEY").expect("Error: SHODAN_API_KEY not found");
        let hostnames = shodan_lookup(public_ip, api_key).await.unwrap();
        assert_eq!(hostnames, vec!["dns.google".to_string()]);
    }

    #[tokio::test]
    async fn test_lookup() {
        let hostnames = vec!["dns.google".to_string()];
        let matches = lookup(hostnames, "8.8.8.8".to_string()).await.unwrap();
        assert_eq!(matches, vec!["dns.google".to_string()])
    }

    #[tokio::test]
    async fn test_reverse_lookup() {
        let public_ip = "8.8.8.8";
        let hostnames = reverse_lookup(public_ip.to_string()).await.unwrap();
        assert_eq!(hostnames, vec!["dns.google.".to_string()])
    }

    #[tokio::test]
    async fn test_lookup_failing() {
        let hostnames = vec!["akamai-inputs-prod-ndia.splunkcloud.com.".to_string()];
        let matches = lookup(hostnames, "8.8.8.8".to_string()).await.unwrap();
        assert_eq!(matches, [] as [String; 0])
    }

    #[tokio::test]
    async fn test_lookup_blacklist() {
        let hostnames = vec!["ec2-3-104-203-50.ap-southeast-2.compute.amazonaws.com".to_string()];
        let matches = lookup(hostnames, "3.104.203.50".to_string()).await.unwrap();
        assert_eq!(matches, [] as [String; 0])
    }

    #[tokio::test]
    async fn test_notify() {
        notify(
            format!("Dangling record found in {} on {} for {} (allocation ID: {})", "eu-west-3", "sites.hotelintelligence.io", "35.181.158.111", "eipalloc-0885edba58eb827e3"),
            ":fishing_pole_and_fish:",
        );
    }
}
