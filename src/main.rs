use std::env;
use aws_sdk_ec2::Client;
use aws_config::meta::region::RegionProviderChain;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use std::error::Error;
use std::time::Duration;
use paris::{error, info, success, warn};
use slack_hook::{Slack, PayloadBuilder};
use clokwerk::{AsyncScheduler, TimeUnits};

#[tokio::main]
async
fn main() {
    let mut scheduler = AsyncScheduler::new();
    scheduler.every(15.seconds()).run(|| async {
        handle().await;
    });

    loop {
        scheduler.run_pending().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle() {
    let (public_ip, allocation_id) = allocate_elastic_ip().await;
    let shodan_api_key = env::var("SHODAN_API_KEY").expect("Error: SHODAN_API_KEY not found");

    let reverse_dns = reverse_lookup(&public_ip, shodan_api_key).await.unwrap();

    if reverse_dns.contains("error") || reverse_dns.contains("amazonaws") || reverse_dns.contains("cloudfront") {
        warn!("No reverse DNS record found");
        notify(format!("No reverse DNS found for Public IP {}", public_ip), ":zero:");
        release_elastic_ip(&allocation_id).await;
    } else {
        notify(format!("Reverse DNS found {} for Public IP {}", reverse_dns, public_ip), ":fishing_pole_and_fish:");
        success!("Reverse DNS record: {}", reverse_dns);
    }
}

fn notify(text: String, icon_emoji: &str) {
    let slack_webhook_url = env::var("SLACK_WEBHOOK_URL").expect("Error: SLACK_WEBHOOK_URL not found");
    let slack = Slack::new(slack_webhook_url.as_str()).unwrap();
    let p = PayloadBuilder::new()
        .text(text)
        .channel("#bots")
        .username("EIP Bot")
        .icon_emoji(icon_emoji)
        .build()
        .unwrap();
    let res = slack.send(&p);
    if res.is_err() {
        error!("Error sending Slack message: {}", res.err().unwrap());
    }
}

async fn allocate_elastic_ip() -> (String, String) {
    let region_provider = RegionProviderChain::default_provider().or_else("ap-southeast-2");
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&config);
    let allocate_response = client.allocate_address().send().await.unwrap();
    let public_ip = allocate_response.public_ip.unwrap();
    let allocation_id = allocate_response.allocation_id.unwrap();
    info!("Elastic IP address: {}", public_ip);
    (public_ip, allocation_id)
}

async fn release_elastic_ip(allocation_id: &str) {
    let region_provider = RegionProviderChain::default_provider().or_else("ap-southeast-2");
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&config);

    let release_response = client.release_address().allocation_id(allocation_id).send().await;
    if release_response.is_err() {
        error!("Error releasing Elastic IP address: {}", release_response.err().unwrap());
    } else {
        success!("Elastic IP address released for allocation ID: {}", allocation_id);
    }
}

async fn reverse_lookup(ip: &str, api_key: String) -> Result<String, Box<dyn Error>> {
    let url = format!("https://api.shodan.io/shodan/host/{}", ip);

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let client = reqwest::Client::builder().default_headers(headers).build()?;
    let res = client
        .get(&url)
        .query(&[("key", api_key)])
        .send()
        .await?
        .text()
        .await?;

    Ok(res)
}