using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sun.Identity.Common;

namespace Fedlet.UnitTests
{
    [TestClass]
    public class LoggerFactoryTests
    {
        [TestMethod]
        public void GetLogger_before_SetFactory_should_return_instance_of_FedletLogger()
        {
            Assert.IsInstanceOfType(LoggerFactory.GetLogger<LoggerFactoryTests>(), typeof(EventLogLogger));
        }

        [TestMethod]
        public void SetFactory_should_replace_the_instance_of_the_static_factory_delegate()
        {
            LoggerFactory.SetFactory(type => null);
            Assert.IsNull(LoggerFactory.GetLogger<LoggerFactoryTests>());
        }
    }
}
