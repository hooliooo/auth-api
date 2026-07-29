#[cfg(test)]
use kern::building_blocks::domain_event::DynDomainEvent;
#[cfg(test)]
use mockall::mock;

pub mod organization;

#[cfg(test)]
mock!(
    pub TestEventPublisher {}

    impl kern::application::event::EventPublisher for TestEventPublisher {
        fn publish(&self, topic: &'static str, event: std::sync::Arc<dyn DynDomainEvent>);
    }
);
