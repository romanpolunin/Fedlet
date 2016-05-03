using NUnit.Framework;
using Sun.Identity.Common;

namespace Fedlet.UnitTests
{
    [TestFixture]
    public class LoggerFactoryTests
    {
        [Test]
        public void GetLogger_before_SetFactory_should_return_instance_of_FedletLogger()
        {
            Assert.IsInstanceOf<EventLogLogger>(LoggerFactory.GetLogger<LoggerFactoryTests>());
        }

        [Test]
        public void SetFactory_should_replace_the_instance_of_the_static_factory_delegate()
        {
            LoggerFactory.SetFactory(type => null);
            Assert.IsNull(LoggerFactory.GetLogger<LoggerFactoryTests>());
        }
    }
}
